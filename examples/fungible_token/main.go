/*
 * Flow Go SDK
 *
 * Copyright 2019-2020 Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/onflow/cadence"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/client"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/examples"
	"github.com/onflow/flow-go-sdk/templates"
)

const (
	FungibleTokenContractsBaseURL = "https://raw.githubusercontent.com/onflow/flow-ft/master/contracts/"

	CustodialDeposit = "CustodialDeposit.cdc"
	FlowToken        = "FlowToken.cdc"
	FungibleToken    = "FungibleToken.cdc"
	TokenForwarding  = "TokenForwarding.cdc"
)

const (
	// More transactions listed here: https://github.com/onflow/flow-ft/tree/master/transactions
	FungibleTokenTransactionsBaseURL = "https://raw.githubusercontent.com/onflow/flow-ft/master/transactions/"

	SetupAccount   = "setup_account.cdc"
	MintTokens     = "mint_tokens.cdc"
	GetSupply      = "get_supply.cdc"
	GetBalance     = "get_balance.cdc"
	TransferTokens = "transfer_tokens.cdc"
)

const (
	KeysJSON = "keys.json"
)

var (
	flowAccessAddress     = os.Getenv("FLOW_ACCESSADDRESS")
	numberOfIterationsStr = os.Getenv("ITERATIONS")

	fungibleTokenAddress flow.Address
	flowTokenAddress     flow.Address

	rootAcctAddr flow.Address
	rootAcctKey  *flow.AccountKey
	rootSigner   crypto.Signer

	accounts    = map[flow.Address]*flow.AccountKey{}
	privateKeys = map[string][]byte{}
	signers     = map[flow.Address]crypto.InMemorySigner{}

	finalizedBlock *flow.BlockHeader
)

func main() {
	if len(flowAccessAddress) == 0 {
		// Default to emulator address
		flowAccessAddress = "127.0.0.1:3569"
	}

	flowRootAccountKey := os.Getenv("FLOW_ROOTPRIVATEKEY")
	flowClient, err := client.New(flowAccessAddress, grpc.WithInsecure())
	examples.Handle(err)
	if len(flowRootAccountKey) == 0 {
		// Load root account of the emulator, if nothing is passed in
		rootAcctAddr, rootAcctKey, rootSigner = examples.RootAccount(flowClient)
	} else {
		// Otherwise, just load with the Key
		rootAcctAddr, rootAcctKey, rootSigner = examples.RootAccountWithKey(flowClient, flowRootAccountKey)
	}

	existingFungibleTokenAddress := os.Getenv("FLOW_FUNGIBLETOKENADDRESS")
	if len(existingFungibleTokenAddress) != 0 {
		fungibleTokenAddress = flow.HexToAddress(existingFungibleTokenAddress)
	}
	existingFlowTokenAddress := os.Getenv("FLOW_FLOWTOKENADDRESS")
	if len(existingFlowTokenAddress) != 0 {
		flowTokenAddress = flow.HexToAddress(existingFlowTokenAddress)
	}

	finalizedBlock, err = flowClient.GetLatestBlockHeader(context.Background(), false)
	examples.Handle(err)

	fmt.Println("Reference Block", finalizedBlock.ID)

	if len(existingFungibleTokenAddress) == 0 || len(existingFlowTokenAddress) == 0 {
		// Deploy the token contracts
		DeployFungibleAndFlowTokens(flowClient)
	}

	numberOfIterations, _ := strconv.Atoi(numberOfIterationsStr)
	if len(numberOfIterationsStr) == 0 {
		numberOfIterations = 10
	}

	b, _ := ioutil.ReadFile(KeysJSON)
	if len(b) > 0 {
		err := json.Unmarshal(b, &privateKeys)
		if err == nil {
			for addrString, key := range privateKeys {
				pk, err := crypto.DecodePrivateKey(crypto.ECDSA_P256, key)
				examples.Handle(err)
				addr := flow.HexToAddress(addrString)
				acc, err := flowClient.GetAccount(context.Background(), addr)
				examples.Handle(err)
				accountKey := acc.Keys[0]

				accounts[addr] = accountKey
				signer := crypto.NewInMemorySigner(pk, accountKey.HashAlgo)
				signers[addr] = signer
			}
		}
	}

	if len(accounts) == 0 {
		fmt.Println("Creating a batch of accounts")
		// createAccountWG := sync.WaitGroup{}
		for i := 0; i < numberOfIterations; i++ {
			// createAccountWG.Add(1)
			// go func() {
			finalizedBlock, err = flowClient.GetLatestBlockHeader(context.Background(), false)
			examples.Handle(err)
			addr, key := CreateAccountAndTransfer(flowClient)
			accounts[addr] = key
			// 	createAccountWG.Done()

			// }()
		}

		keysFile, err := json.MarshalIndent(privateKeys, "", " ")
		if err != nil {
			fmt.Println("Could not save account keys", err)
		} else {
			_ = ioutil.WriteFile(KeysJSON, keysFile, 0644)
		}

	}

	for {
		fmt.Println("Transfering tokens")
		transferWG := sync.WaitGroup{}
		prevAddr := flowTokenAddress
		finalizedBlock, err = flowClient.GetLatestBlockHeader(context.Background(), false)
		examples.Handle(err)

		for accountAddr, accountKey := range accounts {
			transferWG.Add(1)
			go func(fromAddr, toAddr flow.Address, accKey *flow.AccountKey) {
				Transfer10Tokens(flowClient, fromAddr, toAddr, accKey)
				transferWG.Done()
			}(accountAddr, prevAddr, accountKey)
			prevAddr = accountAddr
		}

		transferWG.Wait()
	}

	// GetEvents(flowClient)
	// GetTokenSupply(flowClient)
	// GetAccountBalance(flowClient)
}

func DeployFungibleAndFlowTokens(flowClient *client.Client) {
	ctx := context.Background()
	// Deploy the FT contract
	ftCode, err := examples.DownloadFile(FungibleTokenContractsBaseURL + FungibleToken)
	examples.Handle(err)
	deployFTScript, err := templates.CreateAccount(nil, ftCode)
	examples.Handle(err)

	deployContractTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(deployFTScript).
		SetProposalKey(rootAcctAddr, rootAcctKey.ID, rootAcctKey.SequenceNumber).
		SetPayer(rootAcctAddr)

	err = deployContractTx.SignEnvelope(
		rootAcctAddr,
		rootAcctKey.ID,
		rootSigner,
	)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *deployContractTx)
	examples.Handle(err)

	deployContractTxResp := examples.WaitForFinalized(ctx, flowClient, deployContractTx.ID())
	examples.Handle(deployContractTxResp.Error)

	// Successful Tx, increment sequence number
	rootAcctKey.SequenceNumber++

	for _, event := range deployContractTxResp.Events {
		fmt.Printf("EVENT %+v\n", event)
		fmt.Println(event.ID())
		fmt.Println(event.Type)
		fmt.Println(event.Value)
		if event.Type == flow.EventAccountCreated {
			accountCreatedEvent := flow.AccountCreatedEvent(event)
			fungibleTokenAddress = accountCreatedEvent.Address()
		}
	}

	fmt.Println("FT Address:", fungibleTokenAddress.Hex())

	// Deploy the Flow Token contract
	flowTokenCodeRaw, err := examples.DownloadFile(FungibleTokenContractsBaseURL + FlowToken)
	examples.Handle(err)
	flowTokenCode := strings.ReplaceAll(string(flowTokenCodeRaw), "0x02", "0x"+fungibleTokenAddress.Hex())

	// Use the same root account key for simplicity
	deployFlowTokenScript, err := templates.CreateAccount([]*flow.AccountKey{rootAcctKey}, []byte(flowTokenCode))
	examples.Handle(err)

	deployFlowTokenContractTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(deployFlowTokenScript).
		SetProposalKey(rootAcctAddr, rootAcctKey.ID, rootAcctKey.SequenceNumber).
		SetPayer(rootAcctAddr)

	err = deployFlowTokenContractTx.SignEnvelope(
		rootAcctAddr,
		rootAcctKey.ID,
		rootSigner,
	)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *deployFlowTokenContractTx)
	examples.Handle(err)

	deployFlowTokenContractTxResp := examples.WaitForFinalized(ctx, flowClient, deployFlowTokenContractTx.ID())
	examples.Handle(deployFlowTokenContractTxResp.Error)

	// Successful Tx, increment sequence number
	rootAcctKey.SequenceNumber++

	for _, event := range deployFlowTokenContractTxResp.Events {
		fmt.Printf("%+v\n", event)

		if event.Type == flow.EventAccountCreated {
			accountCreatedEvent := flow.AccountCreatedEvent(event)
			flowTokenAddress = accountCreatedEvent.Address()
		}
	}

	fmt.Println("Flow Token Address:", flowTokenAddress.Hex())
}

func CreateAccountAndTransfer(flowClient *client.Client) (flow.Address, *flow.AccountKey) {
	ctx := context.Background()

	myPrivateKey := examples.RandomPrivateKey()
	accountKey := flow.NewAccountKey().
		FromPrivateKey(myPrivateKey).
		SetHashAlgo(crypto.SHA3_256).
		SetWeight(flow.AccountKeyWeightThreshold)
	mySigner := crypto.NewInMemorySigner(myPrivateKey, accountKey.HashAlgo)

	// Generate an account creation script
	createAccountScript, err := templates.CreateAccount([]*flow.AccountKey{accountKey}, nil)
	examples.Handle(err)

	createAccountTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(createAccountScript).
		SetProposalKey(rootAcctAddr, rootAcctKey.ID, rootAcctKey.SequenceNumber).
		SetPayer(rootAcctAddr)

	err = createAccountTx.SignEnvelope(rootAcctAddr, rootAcctKey.ID, rootSigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *createAccountTx)
	examples.Handle(err)

	accountCreationTxRes := examples.WaitForFinalized(ctx, flowClient, createAccountTx.ID())
	examples.Handle(accountCreationTxRes.Error)

	// Successful Tx, increment sequence number
	rootAcctKey.SequenceNumber++
	accountAddress := flow.Address{}
	for _, event := range accountCreationTxRes.Events {
		fmt.Println(event)

		if event.Type == flow.EventAccountCreated {
			accountCreatedEvent := flow.AccountCreatedEvent(event)
			accountAddress = accountCreatedEvent.Address()
		}
	}

	fmt.Println("My Address:", accountAddress.Hex())

	// Save key and signer
	signers[accountAddress] = mySigner
	privateKeys[accountAddress.String()] = myPrivateKey.Encode()

	// Setup the account
	accountSetupScript := GenerateSetupAccountScript(fungibleTokenAddress, flowTokenAddress)

	accountSetupTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(accountSetupScript).
		SetProposalKey(accountAddress, accountKey.ID, accountKey.SequenceNumber).
		SetPayer(accountAddress).
		AddAuthorizer(accountAddress)

	err = accountSetupTx.SignEnvelope(accountAddress, accountKey.ID, mySigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *accountSetupTx)
	examples.Handle(err)

	accountSetupTxResp := examples.WaitForFinalized(ctx, flowClient, accountSetupTx.ID())
	examples.Handle(accountSetupTxResp.Error)

	// Successful Tx, increment sequence number
	accountKey.SequenceNumber++

	// Mint to the new account
	flowTokenAcc, err := flowClient.GetAccount(context.Background(), flowTokenAddress)
	examples.Handle(err)
	flowTokenAccKey := flowTokenAcc.Keys[0]

	// Mint 10 tokens
	mintScript := GenerateMintScript(fungibleTokenAddress, flowTokenAddress, accountAddress)
	mintTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(mintScript).
		SetProposalKey(accountAddress, accountKey.ID, accountKey.SequenceNumber).
		SetPayer(accountAddress).
		AddAuthorizer(flowTokenAddress)

	err = mintTx.SignPayload(flowTokenAddress, flowTokenAccKey.ID, rootSigner)
	examples.Handle(err)

	err = mintTx.SignEnvelope(accountAddress, accountKey.ID, mySigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *mintTx)
	examples.Handle(err)

	mintTxResp := examples.WaitForFinalized(ctx, flowClient, mintTx.ID())
	examples.Handle(mintTxResp.Error)

	// Successful Tx, increment sequence number
	accountKey.SequenceNumber++
	return accountAddress, accountKey
}

func Transfer10Tokens(flowClient *client.Client, fromAddr, toAddr flow.Address, fromKey *flow.AccountKey) {
	ctx := context.Background()

	// Transfer 10 tokens
	transferScript := GenerateTransferScript(fungibleTokenAddress, flowTokenAddress, toAddr)
	transferTx := flow.NewTransaction().
		SetReferenceBlockID(finalizedBlock.ID).
		SetScript(transferScript).
		SetProposalKey(fromAddr, fromKey.ID, fromKey.SequenceNumber).
		SetPayer(fromAddr).
		AddAuthorizer(fromAddr)

	// err = transferTx.SignPayload(flowTokenAddress, flowTokenAccKey.ID, rootSigner)
	// examples.Handle(err)

	err := transferTx.SignEnvelope(fromAddr, fromKey.ID, signers[fromAddr])
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *transferTx)
	examples.Handle(err)

	transferTxResp := examples.WaitForFinalized(ctx, flowClient, transferTx.ID())

	// Successful Tx, increment sequence number
	fromKey.SequenceNumber++

	if transferTxResp.Error != nil {
		fmt.Println(transferTxResp.Error)
		// Do not fail, so that we can continue loop
		return
	}
}

// GetEvents currently only gets the Deposit event,
// List of possible events for the FlowToken contract: https://github.com/onflow/flow-ft/blob/master/contracts/FlowToken.cdc#L26-L41
func GetEvents(flowClient *client.Client) {
	ctx := context.Background()
	results, err := flowClient.GetEventsForHeightRange(ctx, client.EventRangeQuery{
		Type:        fmt.Sprintf("A.%s.FlowToken.Deposit", flowTokenAddress.Hex()),
		StartHeight: 0,
		EndHeight:   100,
	})
	examples.Handle(err)

	fmt.Println("\nQuery for Deposit event:")
	for _, block := range results {
		for i, event := range block.Events {
			fmt.Printf("Found event #%d in block #%d\n", i+1, block.Height)
			fmt.Printf("Transaction ID: %s\n", event.TransactionID)
			fmt.Printf("Event ID: %s\n", event.ID())
			fmt.Println(event.String())
		}
	}
}

func GetTokenSupply(flowClient *client.Client) {
	ctx := context.Background()
	result, err := flowClient.ExecuteScriptAtLatestBlock(ctx, GenerateSupplyScript(flowTokenAddress))
	examples.Handle(err)

	supply := result.(cadence.UFix64)

	fmt.Printf("Supply of Flow Tokens: %d\n", supply.ToGoValue())
}

func GetAccountBalance(flowClient *client.Client, myAddress flow.Address) {
	ctx := context.Background()
	result, err := flowClient.ExecuteScriptAtLatestBlock(ctx, GenerateBalanceScript(fungibleTokenAddress, flowTokenAddress, myAddress))
	examples.Handle(err)

	supply := result.(cadence.UFix64)

	fmt.Printf("Balance of Flow Tokens for %s: %d\n", myAddress.Hex(), supply.ToGoValue())
}

func GenerateSetupAccountScript(ftAddr, flowToken flow.Address) []byte {
	setupCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + SetupAccount)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(setupCode), "0x02", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.ReplaceAll(string(withFTAddr), "0x03", "0x"+flowToken.Hex())

	return []byte(withFlowTokenAddr)
}

// GenerateMintScript Creates a script that mints an 10 FTs
func GenerateMintScript(ftAddr, flowToken, toAddr flow.Address) []byte {
	mintCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + MintTokens)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(mintCode), "0x02", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.Replace(string(withFTAddr), "0x03", "0x"+flowToken.Hex(), 1)
	withToAddr := strings.Replace(string(withFlowTokenAddr), "0x03", "0x"+toAddr.Hex(), 1)

	withAmount := strings.Replace(string(withToAddr), "10.0", "1.0", 1)

	return []byte(withAmount)
}

// GenerateTransferScript Creates a script that mints an 10 FTs
func GenerateTransferScript(ftAddr, flowToken, toAddr flow.Address) []byte {
	mintCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + TransferTokens)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(mintCode), "0x02", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.Replace(string(withFTAddr), "0x03", "0x"+flowToken.Hex(), 1)
	withToAddr := strings.Replace(string(withFlowTokenAddr), "0x04", "0x"+toAddr.Hex(), 1)

	withAmount := strings.Replace(string(withToAddr), "10.0", "0.01", 1)

	return []byte(withAmount)
}

// GenerateSupplyScript Creates a script that gets the supply of the token
// Currently get the supply at the latest sealed block, possible to get at any sealed block
func GenerateSupplyScript(flowToken flow.Address) []byte {
	supplyCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + GetSupply)
	examples.Handle(err)

	withFlowTokenAddr := strings.Replace(string(supplyCode), "0x03", "0x"+flowToken.Hex(), 1)

	return []byte(withFlowTokenAddr)
}

// GenerateBalanceScript Creates a script looks at the balance of an address
// Currently get the balance at the latest sealed block, possible to get at any sealed block
func GenerateBalanceScript(ftAddr, flowToken, toAddr flow.Address) []byte {
	mintCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + GetBalance)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(mintCode), "0x02", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.Replace(string(withFTAddr), "0x03", "0x"+flowToken.Hex(), 1)
	withToAddr := strings.Replace(string(withFlowTokenAddr), "0x03", "0x"+toAddr.Hex(), 1)

	return []byte(withToAddr)
}
