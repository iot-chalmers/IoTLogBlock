/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

//CGO_LDFLAGS_ALLOW="-I.*"
// docker logs $(docker ps | grep dev-$PEER | awk '{print $1}')
package main

/* Imports
 * 4 utility libraries for formatting, handling bytes, reading and writing JSON, and string manipulation
 * 2 specific Hyperledger Fabric specific libraries for Smart Contracts
 */
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"math/big"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
)

type SmartContract struct {
	SmartCPubKey ecdsa.PublicKey
}

// define Node properties to saved in Blockchain
type IoTNode struct {
	NodeID     string `json:"nodeid"`
	Owner      string `json:"owner"`
	PublicKeyX string `json:"pkeyX"`
	PublicKeyY string `json:"pkeyY"`
}

type IotTranx struct {
	TransactionID string `json:"TX"`
	DeviceID      string `json:"SenderID"`
	HexData       string `json:"HexData"`
	HexNonceR     string `json:"HexNonceR"`
	SignatureO    string `json:"SignatureO"`
	SignatureS    string `json:"SignatureR"`
	NonceO        string `json:"Nonce0"`
	NonceR        string `json:"NonceR"`
}

var logger = shim.NewLogger("IoTLogBlock")

//prefix index for the Transaction
var TXCounter = 0
var TXString = "Tx"

/*
 * The Init method is called when the Smart Contract "IoTLogBlock" is instantiated by the blockchain network
 * Best practice is to have any Ledger initialization in separate function -- see initLedger()
 */
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	s.SmartCPubKey.Curve = elliptic.P256()
	const x = "36dfe2c6f9f2ed29da0a9a8f62684e916375ba10300c28c5e47cfbf25fa58f52"
	decoded, err := hex.DecodeString(x)
	if err != nil {
		log.Fatal(err)
	}
	s.SmartCPubKey.X = big.NewInt(0)
	s.SmartCPubKey.X.SetBytes([]byte(decoded))

	const y = "71a0d4fcde1ab8785a3c786935a7cfabe93f987209daed0b4fabc36fc772f829"
	decoded, err = hex.DecodeString(y)
	if err != nil {
		log.Fatal(err)
	}
	s.SmartCPubKey.Y = big.NewInt(0)
	s.SmartCPubKey.Y.SetBytes([]byte(decoded))

	return shim.Success(nil)
}

/*
 * The Invoke method is called as a result of an application request to run the Smart Contract "IOT"
 * The calling application program has also specified the particular smart contract function to be called, with arguments
 */
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {
	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "initLedger" {
		return s.initLedger(APIstub)
	} else if function == "createIoT" {
		return s.createIoT(APIstub, args)
	} else if function == "IotTrans" {
		return s.IotTrans(APIstub, args)
	} else if function == "queryIot" {
		return s.queryIot(APIstub)
	} else if function == "queryTx" {
		return s.queryTx(APIstub)
	}

	return shim.Error("Invalid Smart Contract function name.")
}
func (s *SmartContract) initLedger(APIstub shim.ChaincodeStubInterface) sc.Response {

	const x = "36dfe2c6f9f2ed29da0a9a8f62684e916375ba10300c28c5e47cfbf25fa58f52"
	const y = "71a0d4fcde1ab8785a3c786935a7cfabe93f987209daed0b4fabc36fc772f829"

	iotNodes := []IoTNode{
		IoTNode{NodeID: "Device1", Owner: "Bob", PublicKeyX: x, PublicKeyY: y},
		IoTNode{NodeID: "Device2", Owner: "Alice", PublicKeyX: x, PublicKeyY: y},
	}

	i := 0
	for i < len(iotNodes) {
		iotAsBytes, _ := json.Marshal(iotNodes[i])
		APIstub.PutState("Device"+strconv.Itoa(i), iotAsBytes)
		fmt.Println("Added", iotNodes[i])
		i = i + 1
	}

	return shim.Success(nil)
}

func (s *SmartContract) IotTrans(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	/* 8 arguments:
	[0] -> TransID    	-> Transaction ID
	[1] -> Device	  	-> ID of the originator
	[2] -> HexData  	-> Hex data of trensaction
	[3] -> HexNonceR  	-> Hex of nonce of responder
	[4] -> SignatureO	-> Signature of Originator
	[5] -> SignatureR  	-> SignatureO of Responder
	[6]	-> NonceO 		-> Nonce of Originator
	[7]	-> NonceR 		-> Nonce of Responder
	*/
	fmt.Println("________ ")
	if len(args) != 8 {
		return shim.Error("Incorrect number of arguments. Expecting 8")
	}
	validNode, _ := APIstub.GetState(args[1])
	var m IoTNode
	err := json.Unmarshal(validNode, &m)
	if err != nil {
		fmt.Printf("Error in json new %s \n", err)
	}
	var pubkey ecdsa.PublicKey
	pubkey.Curve = elliptic.P256()

	decoded, err := hex.DecodeString(string(m.PublicKeyX))
	if err != nil {
		log.Fatal(err)
	}
	pubkey.X = big.NewInt(0)
	pubkey.X.SetBytes([]byte(decoded))

	decoded, err = hex.DecodeString(string(m.PublicKeyY))
	if err != nil {
		log.Fatal(err)
	}
	pubkey.Y = big.NewInt(0)
	pubkey.Y.SetBytes([]byte(decoded))

	//calc the hash of hex data
	var h hash.Hash
	h = sha256.New()
	decoded, err = hex.DecodeString(args[2])
	if err != nil {
		log.Fatal(err)
	}
	h.Write([]byte(decoded))
	msgHash := h.Sum(nil)

	// set r for ecc
	signR := big.NewInt(0)
	const rr = "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
	decoded, err = hex.DecodeString(rr)
	if err != nil {
		log.Fatal(err)
	}
	signR.SetBytes([]byte(decoded))

	//set the signature Originator
	signS := big.NewInt(0)
	decoded, err = hex.DecodeString(args[4])
	if err != nil {
		log.Fatal(err)
	}
	signS.SetBytes([]byte(decoded))
	//Originator Signature Verification
	verifystatus := ecdsa.Verify(&pubkey, msgHash, signR, signS)
	fmt.Println(verifystatus) // must be true

	h = sha256.New()
	// take hex data (args[4]) + nonce  and calcuate the sha256 hash
	fmt.Printf("hex of data: %s \n", args[2]+args[3]
	decoded, err = hex.DecodeString(args[2] + args[3])
	if err != nil {
		log.Fatal(err)
	}
	h.Write([]byte(decoded))
	msgHash = h.Sum(nil)
	fmt.Printf("Hash of data: %x \n", msgHash)

	signS = big.NewInt(0)

	// verify the signature of responder
	decoded, err = hex.DecodeString(args[5])
	fmt.Printf("sign of respond: %x \n", args[5])
	if err != nil {
		log.Fatal(err)
	}
	signS.SetBytes([]byte(decoded))
	//Signature Verification
	verifystatus = ecdsa.Verify(&pubkey, msgHash, signR, signS)
	fmt.Println(verifystatus) // should be true

	//add valid transaction to the chain
	var trans = IotTranx{TransactionID: args[0], DeviceID: args[1], HexData: args[2], HexNonceR: args[3], SignatureO: args[4], SignatureS: args[5], NonceO: args[6], NonceR: args[7]}

	IotTransAsBytes, _ := json.Marshal(trans)

	APIstub.PutState(TXString+strconv.Itoa(TXCounter), IotTransAsBytes)
	TXCounter++
	fmt.Println("________ ")
	return shim.Success(nil)

}

func (s *SmartContract) queryTx(APIstub shim.ChaincodeStubInterface) sc.Response {

	startKey := "Tx0"
	endKey := "Tx9999"

	resultsIterator, err := APIstub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()
	//test
	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	fmt.Printf("- queryIOT:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

func (s *SmartContract) createIoT(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	/*
		args:
		[0] -> Node ID
		[1] -> Owner
		[2] -> X coordinate of Public Key
		[3] -> Y Coordinate of Public key
	*/

	if len(args) != 4 {
		return shim.Error("Incorrect number of arguments. Expecting 4")
	}
	//Create the public key for the new node

	var iot = IoTNode{NodeID: args[0], Owner: args[1], PublicKeyX: args[2], PublicKeyY: args[3]}

	IoTAsBytes, _ := json.Marshal(iot)
	APIstub.PutState(args[0], IoTAsBytes)

	return shim.Success(nil)
}

func (s *SmartContract) queryIot(APIstub shim.ChaincodeStubInterface) sc.Response {

	startKey := "Device0"
	endKey := "Device999"

	resultsIterator, err := APIstub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	fmt.Printf("- queryIOT:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

	// Create a new Smart Contract
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
