# Thales Tendermint HSM Validator

Validators are a core component of a blockchain and are responsible for validating new transactions and agreeing an canonical order for the next block. This process is known as *consensus*.

[Tendermint](https://tendermint.com/) is a popular consensus engine used by many open source projects. In conjunction with Tendermint developers, Thales eSecurity has introduced the ability to protect validator signing keys and consensus logic using a hardware security module (HSM). This project contains the Go parts of the HSM validator implementation, which communicate with the software running inside the [Thales nShield HSM](https://www.thalesesecurity.com/products/general-purpose-hsms/nshield-connect).

![Thales HSM](https://www.thalesesecurity.com/sites/default/files/inline-images/product-img-nshield-connect.jpg)

## Why protect validators with HSMs?

Large, public blockchains, such as Bitcoin or Ethereum, enjoy robust security properties due to their sheer scale. To compromise one of these networks requires control of over 50% of the mining power on the planet. Not a realistic option for attackers.

By contrast, smaller permissioned chains must rely on traditional means of security to prevent bad actors from subverting the ledger contents. When you have only 5 or 10 nodes, subverting the necessary 1/3 of participants becomes a realistic prospect if insufficient protections are employed to protect signing keys and consensus logic.

## Thales HSM PrivValidator

At Thales eSecurity we have helped design the Tendermint `PrivValidator` interface ([link](https://github.com/tendermint/tendermint/blob/master/types/priv_validator.go)), which we implement in this GitHub project. A `PrivValidator` implementation is reponsible for protecting a private key and deciding whether to sign votes, proposals and heartbeats (see [this page](https://tendermint.readthedocs.io/en/master/introduction.html#consensus-overview) for an overview of the consensus protocol).

Our implementation protects the private key within our HSM security model and  ensures that votes and proposals cannot be double-signed (by preventing height regressions).

The complete implementation includes the Go code presented in this project, plus an accompanying CodeSafe machine that runs within the nShield HSM. The CodeSafe machine ensures the private keys are only used if the consensus is executed correctly.

## To learn more

If you would like to learn more about this project, please contact us via our website: https://www.thalesesecurity.com.