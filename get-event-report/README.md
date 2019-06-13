# Get event report and create a HTML table
In this example PHP script we do the following:
1. Get the latest vulnerability report for the given organization.
2. Generate a vulnerability report for the last week.
3. Create HTML tables using the reports' JSON content

# Required PHP libraries
* OAuth 2.0 Client from the League of Extraordinary Packages
  - Download [here](https://github.com/thephpleague/oauth2-client)
  - Or install using composer with 
  
  ```$ composer require league/oauth2-client``` 
