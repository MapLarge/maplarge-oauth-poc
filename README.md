# Readme

This repository contains the MapLarge OAuth Plugin Proof of Concept. It contains the plugin, integration tests and support tools to run the integration test.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

See deployment for notes on how to deploy the project on a live system.

### Prerequisites
* Visual Studio 2017
* MapLarge Server or MapLarge Server binaries
* A running instance of IdentityServer4Demo

In order to run the contained integration tests the Maplarge system should be setup in your development environment. Or at a minimum the assemblies from the bin directory of the deployed MapLarge server.  The test rely on the included identity server.

To start the identity server open a command line window and navigate to the tools/IdentityServer4Demo location. 
```
cd c:\src\slb-development\tools\IdentityServer4Demo
```
Then run the following to start the server.
```
dotnet .\IdentityServer4Demo.dll
```



## Running the tests

To run the tests open the solution in visual studio. Build then execute the tests by running all the tests. Results should be displayed in the Test Explorer.
The test test 
* ##### TestClientCredentials
    tests a token issued using the grant_type : client_credentials
* ##### TestPassword
     tests a token issued using the grant_type : password using a username and password.

















