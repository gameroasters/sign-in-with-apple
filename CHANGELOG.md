# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## Changed
- expose `decode_token` fn publicly
- allow decoding token with different `Claims`

## Fixed
- make `Error` public
- email claims need to be optional since user might not grant them

## [0.1.2] - 2021-07-01

## Changed
- remove `Cargo.lock` as we are just a library

## [0.1.1] - 2021-06-05

## Changed
- bumped dependencies and pin to tokio `1`-major due to api stability promise
- error enum renames to not use `Error`-postfix

## Added
- changelog