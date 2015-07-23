# auth_api

Allows direct dbs via a private key, intended for internal use and demonstration.

## Getting Started

### WARNING!!!
Currently requires the branched dao, mongrel2 and swagger-def - 'genericIO'
Additionally, requires a 'dbkeys' bucket in the form of 'dbname={"key":"<thekey>"}' or 'key={'dbs':["mydb"]}'

**DBkeys needs to have at least one document:**
* dbkeys_29f81fe0-3097-4e39-975f-50c4bf8698c7 = { "dbs": [ "users", 
"clients", "authorizations", "queries" ] }


Install the module with: `npm install git+ssh://git@github.com:peat-platform/crud_api.git`

You will need to install the following through macports or aptitude.

```bash
sudo port install JsCoverage
sudo port install phantomjs
```

or

```bash
sudo apt-get install JsCoverage
sudo apt-get install phantomjs
```

To build the project enter the following commands. Note: npm install is only required the first time the module is built or if a new dependency is added. There are a number of grunt tasks that can be executed including: test, cover, default and jenkins. The jenkins task is executed on the build server, if it doesn't pass then the build will fail.

```bash
git clone git@gitlab.peat-platform.eu:crud_api.git
cd crud_api
npm install
grunt jenkins
```

To start the component enter:

```javascript
node lib/local-runner.js
```

## Documentation

API documentation can be found on the PEAT website (http://dev.peat-platform.eu/api-docs/#!/crud).

## License
Copyright (c) 2014
Licensed under the MIT license.
