# Emulator Examples

This package contains code samples that interact with the [Flow Emulator](https://github.com/onflow/flow/blob/master/docs/emulator.md).

## Running the emulator with the Flow CLI

The emulator is bundled with the [Flow CLI](https://github.com/onflow/flow/blob/master/docs/cli.md), a command-line interface for working with Flow.

### Installation

Follow [these steps](https://github.com/onflow/flow/blob/master/docs/cli.md) to install the Flow CLI.

### Starting the server

Start the emulator by running the following command _in this directory_:	

```sh
flow emulator start -v

# The -v flag enables verbose log output, which is useful for testing
```

## Running the examples

In separate process, run any of the example programs below. 
Watch the emulator logs to see transaction output.

```shell script
# Create a new account
GO111MODULE=on go run ./create_account/main.go
```

```shell script
# Add a key to an existing account
GO111MODULE=on go run ./add_account_key/main.go
```

```shell script
# Deploy a contract
GO111MODULE=on go run ./deploy_contract/main.go
```

```shell script
# Query events
GO111MODULE=on go run ./query_events/main.go
```

```shell script
# Query events
GO111MODULE=on go run ./fungible_token/main.go
```
For the fungible token script, there are a few configurable options via Environmental Variables:
```
FLOW_ACCESSADDRESS=
FLOW_ROOTPRIVATEKEY=
FLOW_FUNGIBLETOKENADDRESS=
FLOW_FLOWTOKENADDRESS=
ITERATIONS=
```
Leaving them blank will connect to a locally running emulator, with the preset private key, and deploy new fungible/flow token contracts