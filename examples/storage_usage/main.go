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
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/templates"
	"google.golang.org/grpc"

	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/client"
	"github.com/onflow/flow-go-sdk/examples"
)

func main() {
	StorageUsageDemo()
}

func StorageUsageDemo() {
	ctx := context.Background()
	flowClient, err := client.New("127.0.0.1:3569", grpc.WithInsecure())
	examples.Handle(err)

	serviceAcctAddr, serviceAcctKey, serviceSigner := examples.ServiceAccount(flowClient)

	// Deploy a contract with an event defined
	contract := `
		pub contract StorageDemo {
			pub resource StorageTestResource {
				pub let s: String
				init(s: String) {
					self.s = s
				}
			}
			pub fun createStorageTestResource(s: String): @StorageTestResource {
				return <- create StorageTestResource(s: s)
			}
		}
	`
	privateKey := examples.RandomPrivateKey()

	key := flow.NewAccountKey().
		SetPublicKey(privateKey.PublicKey()).
		SetSigAlgo(privateKey.Algorithm()).
		SetHashAlgo(crypto.SHA3_256).
		SetWeight(flow.AccountKeyWeightThreshold)

	keySigner := crypto.NewInMemorySigner(privateKey, key.HashAlgo)

	contractAccount := examples.CreateAccountWithContracts(flowClient,
		[]*flow.AccountKey{key}, []templates.Contract{{
			Name:   "StorageDemo",
			Source: contract,
		}})

	// Send a tx that emits the event in the deployed contract
	script := fmt.Sprintf(`
		import StorageDemo from 0x%s

		transaction {
			prepare(acct: AuthAccount) {
				let storageUsed = acct.storageUsed
				let storageCapacity = acct.storageUsed
				if (storageUsed > storageCapacity){
					panic("storing too much data!")
				}
			}
		}
	`, contractAccount.Address.Hex())

	referenceBlockID := examples.GetReferenceBlockId(flowClient)
	runScriptTx := flow.NewTransaction().
		SetScript([]byte(script)).
		SetPayer(serviceAcctAddr).
		AddAuthorizer(contractAccount.Address).
		SetReferenceBlockID(referenceBlockID).
		SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber + 1)

	err = runScriptTx.SignPayload(contractAccount.Address, contractAccount.Keys[0].Index, keySigner)
	examples.Handle(err)

	err = runScriptTx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner)
	examples.Handle(err)

	err = flowClient.SendTransaction(ctx, *runScriptTx)
	examples.Handle(err)

	examples.WaitForSeal(ctx, flowClient, runScriptTx.ID())
}
