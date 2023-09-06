# TMC Admin Kubeconfig Decrypt

This is a very simple go cli tool that will take in an encrypted kubeconfig that is returned by the TMC API and decrypt it. The use case for this is if you need to download an admin kubeconfig from tmc for automation purposes but do not want to install the full TMC CLI plugin set and the Tanzu CLI.

## Building
If you need to build this, use the below command. alternatively use the prebuilt binaries in the releases. 


```bash
go build -o tmckube main.go
```

## Usage

### Generate an RSA key pair

This will be used to send to the TMC api as well as for the decryption.

```bash
openssl genrsa -out private-key.pem 4096
openssl rsa -in private-key.pem -RSAPublicKey_out -out public-key.pem

```

### Make the TMC api call for the kubeconfig

set all of the below variables and run the curl command. Timestamp is important here since it needs to match between the curl call and the decrypt command. 

```bash
TMC_HOST="<tmc-hostname>"
PUBLIC_KEY=$(cat public-key.pem | base64)
CLUSTER_NAME="<cluster-name>"
MGMT_CLUSTER="<mgmt-cluster-name>"
PROVISIONER="<provisioner-name>"
TIMESTAMP=$(date "+%Y-%m-%dT%H:%M:%SZ")
TMC_TOKEN="<tmc api token>"
curl "https://${TMC_HOST}/v1alpha1/clusters/${CLUSTER_NAME}/adminkubeconfig?fullName.managementClusterName=${MGMT_CLUSTER}&fullName.provisionerName=${PROVISIONER}&encryptionKey.timestamp=${TIMESTAMP}&encryptionKey.PublicKeyPem=${PUBLIC_KEY}" -H 'accept: application/json' -H "authorization: Bearer ${TMC_TOKEN}" -H 'content-type: application/json' | jq -r .kubeconfig > ${CLUSTER_NAME}-kubeconfig
```


### Run the command to decrypt 

Run the command to decrypt. Be sure to sure the same timestamp from above. 

```bash
./tmckube -private ./private-key.pem -kubeconfig ./${CLUSTER_NAME}-kubeconfig -timestamp ${TIMESTAMP}
```

The output of this should be a decrypted useable kubeconfig
