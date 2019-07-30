This is a web application built on microservices architecture.

1. Make sure the directories other than configService have pem/others and pem/ and pem/others/ are empty.
2. Make sure each conf.json in the directories other than configService corresponds to each JSON file
    in configService directory.
3. Make sure IP Addresses of configService are consistent every places including configService/configServiceConfig.json, accountService/main.go, tlsSetup.go and webClientService/main.go.
4. listMicroservices declared in configService/main.go should be configured to include all microservices.


Run servers in an order (confService => tlsSetup.go => accountService => webClientService)

configService
    Being accessed to "/", it returned JSON over HTTP, in which configuration of all the microservices are denoted.

tlsSetup.go
    With JSON given by configService, it set up pem directories inside microservices other than configService. 

accountService

webClientService