


# keyring

> Access the System Credential Store from R

[![Linux Build Status](https://travis-ci.org/gaborcsardi/keyring.svg?branch=master)](https://travis-ci.org/gaborcsardi/keyring)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/github/gaborcsardi/keyring?svg=true)](https://ci.appveyor.com/project/gaborcsardi/keyring)
[![](http://www.r-pkg.org/badges/version/keyring)](http://www.r-pkg.org/pkg/keyring)
[![CRAN RStudio mirror downloads](http://cranlogs.r-pkg.org/badges/keyring)](http://www.r-pkg.org/pkg/keyring)
[![Coverage Status](https://img.shields.io/codecov/c/github/gaborcsardi/keyring/master.svg)](https://codecov.io/github/gaborcsardi/keyring?branch=master)

Platform independent API to accdss the operating systems
credential store. Currently supports: Keychain on macOS, Credential
Store on Windows, the Secret Service API on Linux, and a simple,
platform independent store implemented with environment variables.
Additional storage backends can be added easily.

## Installation


```r
source("https://install-github.me/gaborcsardi/keyring")
```

## Usage


```r
library(keyring)
```

## License

MIT © RStudio
