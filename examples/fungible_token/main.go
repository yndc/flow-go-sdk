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
	"fmt"
	"os"
	"strings"

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

	SetupAccount = "setup_account.cdc"
	MintTokens   = "mint_tokens.cdc"
	GetSupply    = "get_supply.cdc"
	GetBalance   = "get_balance.cdc"
)

var (
	flowAccessAddress     = os.Getenv("FLOW_ACCESSADDRESS")
	numberOfIterationsStr = os.Getenv("ITERATIONS")

	fungibleTokenAddress flow.Address
	flowTokenAddress     flow.Address
	myAddress            flow.Address // Latest created account

	rootAcctAddr flow.Address
	rootAcctKey  *flow.AccountKey
	rootSigner   crypto.Signer
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

	if len(existingFungibleTokenAddress) == 0 || len(existingFlowTokenAddress) == 0 {
		// Deploy the token contracts
		DeployFungibleAndFlowTokens(flowClient)
	}

	// numberOfIterations, _ := strconv.Atoi(numberOfIterationsStr)
	// if len(numberOfIterationsStr) == 0 {
	// 	numberOfIterations = 1
	// }
	// for i := 0; i < numberOfIterations; i++ {
	// 	CreateAccountAndTransfer(flowClient)
	// }

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

	deployContractTx := flow.NewTransaction().
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

	deployContractTxResp := examples.WaitForSeal(ctx, flowClient, deployContractTx.ID())
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
	flowTokenCode := strings.ReplaceAll(string(flowTokenCodeRaw), "0x01", "0x"+fungibleTokenAddress.Hex())

	// Use the same root account key for simplicity
	deployFlowTokenScript, err := templates.CreateAccount([]*flow.AccountKey{rootAcctKey}, []byte(flowTokenCode))

	deployFlowTokenContractTx := flow.NewTransaction().
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

	deployFlowTokenContractTxResp := examples.WaitForSeal(ctx, flowClient, deployFlowTokenContractTx.ID())
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

func CreateAccountAndTransfer(flowClient *client.Client) {
	ctx := context.Background()

	myPrivateKey := examples.RandomPrivateKey()
	myAcctKey := flow.NewAccountKey().
		FromPrivateKey(myPrivateKey).
		SetHashAlgo(crypto.SHA3_256).
		SetWeight(flow.AccountKeyWeightThreshold)
	mySigner := crypto.NewInMemorySigner(myPrivateKey, myAcctKey.HashAlgo)

	// Generate an account creation script
	createAccountScript, err := templates.CreateAccount([]*flow.AccountKey{myAcctKey}, nil)
	examples.Handle(err)

	createAccountTx := flow.NewTransaction().
		SetScript(createAccountScript).
		SetProposalKey(rootAcctAddr, rootAcctKey.ID, rootAcctKey.SequenceNumber).
		SetPayer(rootAcctAddr)

	err = createAccountTx.SignEnvelope(rootAcctAddr, rootAcctKey.ID, rootSigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *createAccountTx)
	examples.Handle(err)

	accountCreationTxRes := examples.WaitForSeal(ctx, flowClient, createAccountTx.ID())
	examples.Handle(accountCreationTxRes.Error)

	// Successful Tx, increment sequence number
	rootAcctKey.SequenceNumber++

	for _, event := range accountCreationTxRes.Events {
		fmt.Println(event)

		if event.Type == flow.EventAccountCreated {
			accountCreatedEvent := flow.AccountCreatedEvent(event)
			myAddress = accountCreatedEvent.Address()
		}
	}

	fmt.Println("My Address:", myAddress.Hex())

	// Setup the account
	accountSetupScript := GenerateSetupAccountScript(fungibleTokenAddress, flowTokenAddress)

	accountSetupTx := flow.NewTransaction().
		SetScript(accountSetupScript).
		SetProposalKey(myAddress, myAcctKey.ID, myAcctKey.SequenceNumber).
		SetPayer(myAddress).
		AddAuthorizer(myAddress)

	err = accountSetupTx.SignEnvelope(myAddress, myAcctKey.ID, mySigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *accountSetupTx)
	examples.Handle(err)

	accountSetupTxResp := examples.WaitForSeal(ctx, flowClient, accountSetupTx.ID())
	examples.Handle(accountSetupTxResp.Error)

	// Successful Tx, increment sequence number
	myAcctKey.SequenceNumber++

	// Mint to the new account
	flowTokenAcc, err := flowClient.GetAccount(context.Background(), flowTokenAddress)
	examples.Handle(err)
	flowTokenAccKey := flowTokenAcc.Keys[0]

	// Mint 10 tokens
	mintScript := GenerateMintScript(fungibleTokenAddress, flowTokenAddress, myAddress)
	mintTx := flow.NewTransaction().
		SetScript(mintScript).
		SetProposalKey(myAddress, myAcctKey.ID, myAcctKey.SequenceNumber).
		SetPayer(myAddress).
		AddAuthorizer(flowTokenAddress)

	err = mintTx.SignPayload(flowTokenAddress, flowTokenAccKey.ID, rootSigner)
	examples.Handle(err)

	err = mintTx.SignEnvelope(myAddress, myAcctKey.ID, mySigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *mintTx)
	examples.Handle(err)

	mintTxResp := examples.WaitForSeal(ctx, flowClient, mintTx.ID())
	examples.Handle(mintTxResp.Error)

	// Successful Tx, increment sequence number
	myAcctKey.SequenceNumber++
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

func GetAccountBalance(flowClient *client.Client) {
	ctx := context.Background()
	result, err := flowClient.ExecuteScriptAtLatestBlock(ctx, GenerateBalanceScript(fungibleTokenAddress, flowTokenAddress, myAddress))
	examples.Handle(err)

	supply := result.(cadence.UFix64)

	fmt.Printf("Balance of Flow Tokens for %s: %d\n", myAddress.Hex(), supply.ToGoValue())
}

func GenerateSetupAccountScript(ftAddr, flowToken flow.Address) []byte {
	setupCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + SetupAccount)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(setupCode), "0x01", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.ReplaceAll(string(withFTAddr), "0x02", "0x"+flowToken.Hex())

	return []byte(withFlowTokenAddr)
}

// GenerateMintScript Creates a script that mints an 10 FTs
func GenerateMintScript(ftAddr, flowToken, toAddr flow.Address) []byte {
	mintCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + MintTokens)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(mintCode), "0x01", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.Replace(string(withFTAddr), "0x02", "0x"+flowToken.Hex(), 1)
	withToAddr := strings.Replace(string(withFlowTokenAddr), "0x02", "0x"+toAddr.Hex(), 1)

	return []byte(withToAddr)
}

// GenerateSupplyScript Creates a script that gets the supply of the token
// Currently get the supply at the latest sealed block, possible to get at any sealed block
func GenerateSupplyScript(flowToken flow.Address) []byte {
	supplyCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + GetSupply)
	examples.Handle(err)

	withFlowTokenAddr := strings.Replace(string(supplyCode), "0x02", "0x"+flowToken.Hex(), 1)

	return []byte(withFlowTokenAddr)
}

// GenerateBalanceScript Creates a script looks at the balance of an address
// Currently get the balance at the latest sealed block, possible to get at any sealed block
func GenerateBalanceScript(ftAddr, flowToken, toAddr flow.Address) []byte {
	mintCode, err := examples.DownloadFile(FungibleTokenTransactionsBaseURL + GetBalance)
	examples.Handle(err)

	withFTAddr := strings.ReplaceAll(string(mintCode), "0x01", "0x"+ftAddr.Hex())
	withFlowTokenAddr := strings.Replace(string(withFTAddr), "0x02", "0x"+flowToken.Hex(), 1)
	withToAddr := strings.Replace(string(withFlowTokenAddr), "0x02", "0x"+toAddr.Hex(), 1)

	return []byte(withToAddr)
}
