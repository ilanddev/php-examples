# Web socket example
In this example PHP script we do the following:
1. Connect to iland's event websocket
2. Authenticate the websocket.
3. Process events from the websocket and print out information. 

# Required PHP libraries
* OAuth 2.0 Client from the League of Extraordinary Packages
  - Download [here](https://github.com/thephpleague/oauth2-client)
  - Or install using composer with 
  
  ```$ composer require league/oauth2-client``` 
  
* Pawl Websocket Client
  - Download [here](https://github.com/ratchetphp/Pawl)
  - Or install using composer with
 
    ```$ composer require ratchet/pawl```