/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  Provider,
  BlockTag,
  TransactionReceipt,
  TransactionResponse,
  TransactionRequest,
} from '@ethersproject/abstract-provider'
import { Signer } from '@ethersproject/abstract-signer'
import {
  ethers,
  BigNumber,
  Overrides,
  CallOverrides,
  PayableOverrides,
} from 'ethers'
import {
  sleep,
  remove0x,
  toHexString,
  toRpcHexString,
  hashWithdrawal,
  encodeCrossDomainMessageV0,
  hashCrossDomainMessage,
  L2OutputOracleParameters,
  BedrockOutputData,
  BedrockCrossChainMessageProof,
} from '@eth-optimism/core-utils'
import * as rlp from 'rlp'
import { getContractInterface } from '@eth-optimism/contracts-bedrock/dist/contract-defs'

import {
  CoreCrossChainMessage,
  ICrossChainMessenger,
  OEContracts,
  OEContractsLike,
  MessageLike,
  MessageRequestLike,
  TransactionLike,
  AddressLike,
  NumberLike,
  SignerOrProviderLike,
  CrossChainMessage,
  CrossChainMessageRequest,
  CrossChainMessageProof,
  MessageDirection,
  MessageStatus,
  TokenBridgeMessage,
  MessageReceipt,
  MessageReceiptStatus,
  BridgeAdapterData,
  BridgeAdapters,
  StateRoot,
  StateRootBatch,
  IBridgeAdapter,
} from './interfaces'
import {
  toSignerOrProvider,
  toNumber,
  toTransactionHash,
  DeepPartial,
  getAllOEContracts,
  getBridgeAdapters,
  makeMerkleTreeProof,
  makeStateTrieProof,
  DEPOSIT_CONFIRMATION_BLOCKS,
  CHAIN_BLOCK_TIMES,
} from './utils'

export const predeploys = {
  L2ToL1MessagePasser: '0x4200000000000000000000000000000000000000',
  //DeployerWhitelist: '0x4200000000000000000000000000000000000002',
  L2CrossDomainMessenger: '0x4200000000000000000000000000000000000007',
  GasPriceOracle: '0x420000000000000000000000000000000000000F',
  L2StandardBridge: '0x4200000000000000000000000000000000000010',
  //SequencerFeeVault: '0x4200000000000000000000000000000000000011',
  L2StandardTokenFactory: '0x4200000000000000000000000000000000000012',
  L1BlockNumber: '0x4200000000000000000000000000000000000013',

  // // We're temporarily disabling OVM_ETH because the jury is still out on whether or not ETH as an
  // // ERC20 is desirable.
  OVM_ETH: '0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000',

  // // We're also putting WETH9 at the old OVM_ETH address.
  // WETH9: '0x4200000000000000000000000000000000000006',
}

export class CrossChainMessenger implements ICrossChainMessenger {
  public l1SignerOrProvider: Signer | Provider
  public l2SignerOrProvider: Signer | Provider
  public l1ChainId: number
  public l2ChainId: number
  public contracts: OEContracts
  public bridges: BridgeAdapters
  public depositConfirmationBlocks: number
  public l1BlockTimeSeconds: number
  public bedrock: boolean

  private _l2OutputOracleParameters: L2OutputOracleParameters

  /**
   * Creates a new CrossChainProvider instance.
   *
   * @param opts Options for the provider.
   * @param opts.l1SignerOrProvider Signer or Provider for the L1 chain, or a JSON-RPC url.
   * @param opts.l2SignerOrProvider Signer or Provider for the L2 chain, or a JSON-RPC url.
   * @param opts.l1ChainId Chain ID for the L1 chain.
   * @param opts.l2ChainId Chain ID for the L2 chain.
   * @param opts.depositConfirmationBlocks Optional number of blocks before a deposit is confirmed.
   * @param opts.l1BlockTimeSeconds Optional estimated block time in seconds for the L1 chain.
   * @param opts.contracts Optional contract address overrides.
   * @param opts.bridges Optional bridge address list.
   * @param opts.bedrock Whether or not to enable Bedrock compatibility.
   */
  constructor(opts: {
    l1SignerOrProvider: SignerOrProviderLike
    l2SignerOrProvider: SignerOrProviderLike
    l1ChainId: NumberLike
    l2ChainId: NumberLike
    depositConfirmationBlocks?: NumberLike
    l1BlockTimeSeconds?: NumberLike
    contracts?: DeepPartial<OEContractsLike>
    bridges?: BridgeAdapterData
    bedrock?: boolean
  }) {
    this.bedrock = opts.bedrock ?? false
    this.l1SignerOrProvider = toSignerOrProvider(opts.l1SignerOrProvider)
    this.l2SignerOrProvider = toSignerOrProvider(opts.l2SignerOrProvider)

    try {
      this.l1ChainId = toNumber(opts.l1ChainId)
    } catch (err) {
      throw new Error(`L1 chain ID is missing or invalid: ${opts.l1ChainId}`)
    }

    try {
      this.l2ChainId = toNumber(opts.l2ChainId)
    } catch (err) {
      throw new Error(`L2 chain ID is missing or invalid: ${opts.l2ChainId}`)
    }

    this.depositConfirmationBlocks =
      opts?.depositConfirmationBlocks !== undefined
        ? toNumber(opts.depositConfirmationBlocks)
        : DEPOSIT_CONFIRMATION_BLOCKS[this.l2ChainId] || 0

    this.l1BlockTimeSeconds =
      opts?.l1BlockTimeSeconds !== undefined
        ? toNumber(opts.l1BlockTimeSeconds)
        : CHAIN_BLOCK_TIMES[this.l1ChainId] || 1

    this.contracts = getAllOEContracts(this.l2ChainId, {
      l1SignerOrProvider: this.l1SignerOrProvider,
      l2SignerOrProvider: this.l2SignerOrProvider,
      overrides: opts.contracts,
    })

    this.bridges = getBridgeAdapters(this.l2ChainId, this, {
      overrides: opts.bridges,
    })
  }

  get l1Provider(): Provider {
    if (Provider.isProvider(this.l1SignerOrProvider)) {
      return this.l1SignerOrProvider
    } else {
      return this.l1SignerOrProvider.provider
    }
  }

  get l2Provider(): Provider {
    if (Provider.isProvider(this.l2SignerOrProvider)) {
      return this.l2SignerOrProvider
    } else {
      return this.l2SignerOrProvider.provider
    }
  }

  get l1Signer(): Signer {
    if (Provider.isProvider(this.l1SignerOrProvider)) {
      throw new Error(`messenger has no L1 signer`)
    } else {
      return this.l1SignerOrProvider
    }
  }

  get l2Signer(): Signer {
    if (Provider.isProvider(this.l2SignerOrProvider)) {
      throw new Error(`messenger has no L2 signer`)
    } else {
      return this.l2SignerOrProvider
    }
  }

  public async getL2OutputOracleParameters(): Promise<L2OutputOracleParameters> {
    if (this._l2OutputOracleParameters) {
      return this._l2OutputOracleParameters
    }

    this._l2OutputOracleParameters = {
      submissionInterval: (
        await this.contracts.l1.L2OutputOracle.SUBMISSION_INTERVAL()
      ).toNumber(),
      startingBlockNumber: (
        await this.contracts.l1.L2OutputOracle.STARTING_BLOCK_NUMBER()
      ).toNumber(),
      l2BlockTime: (
        await this.contracts.l1.L2OutputOracle.L2_BLOCK_TIME()
      ).toNumber(),
    }

    return this._l2OutputOracleParameters
  }

  public async getMessagesByTransaction(
    transaction: TransactionLike,
    opts: {
      direction?: MessageDirection
    } = {}
  ): Promise<CrossChainMessage[]> {
    // Wait for the transaction receipt if the input is waitable.
    await (transaction as TransactionResponse).wait?.()

    // Convert the input to a transaction hash.
    const txHash = toTransactionHash(transaction)

    let receipt: TransactionReceipt
    if (opts.direction !== undefined) {
      // Get the receipt for the requested direction.
      if (opts.direction === MessageDirection.L1_TO_L2) {
        receipt = await this.l1Provider.getTransactionReceipt(txHash)
      } else {
        receipt = await this.l2Provider.getTransactionReceipt(txHash)
      }
    } else {
      // Try both directions, starting with L1 => L2.
      receipt = await this.l1Provider.getTransactionReceipt(txHash)
      if (receipt) {
        opts.direction = MessageDirection.L1_TO_L2
      } else {
        receipt = await this.l2Provider.getTransactionReceipt(txHash)
        opts.direction = MessageDirection.L2_TO_L1
      }
    }

    if (!receipt) {
      throw new Error(`unable to find transaction receipt for ${txHash}`)
    }

    // By this point opts.direction will always be defined.
    const messenger =
      opts.direction === MessageDirection.L1_TO_L2
        ? this.contracts.l1.L1CrossDomainMessenger
        : this.contracts.l2.L2CrossDomainMessenger

    return receipt.logs
      .filter((log) => {
        // Only look at logs emitted by the messenger address
        return log.address === messenger.address
      })
      .filter((log) => {
        // Only look at SentMessage logs specifically
        const parsed = messenger.interface.parseLog(log)
        return parsed.name === 'SentMessage'
      })
      .map((log) => {
        // Try to pull out the value field, but only if the very next log is a SentMessageExtraData
        // event which was introduced in the Bedrock upgrade.
        let value = ethers.BigNumber.from(0)
        const next = receipt.logs.find((l) => {
          return (
            l.logIndex === log.logIndex + 1 && l.address === messenger.address
          )
        })
        if (next) {
          const nextParsed = messenger.interface.parseLog(next)
          if (nextParsed.name === 'SentMessageExtension1') {
            value = nextParsed.args.value
          }
        }

        // Convert each SentMessage log into a message object
        const parsed = messenger.interface.parseLog(log)
        return {
          direction: opts.direction,
          target: parsed.args.target,
          sender: parsed.args.sender,
          message: parsed.args.message,
          messageNonce: parsed.args.messageNonce,
          value,
          minGasLimit: parsed.args.gasLimit,
          logIndex: log.logIndex,
          blockNumber: log.blockNumber,
          transactionHash: log.transactionHash,
        }
      })
  }

  // public async getMessagesByAddress(
  //   address: AddressLike,
  //   opts?: {
  //     direction?: MessageDirection
  //     fromBlock?: NumberLike
  //     toBlock?: NumberLike
  //   }
  // ): Promise<CrossChainMessage[]> {
  //   throw new Error(`
  //     The function getMessagesByAddress is currently not enabled because the sender parameter of
  //     the SentMessage event is not indexed within the CrossChainMessenger contracts.
  //     getMessagesByAddress will be enabled by plugging in an Optimism Indexer (coming soon).
  //     See the following issue on GitHub for additional context:
  //     https://github.com/ethereum-optimism/optimism/issues/2129
  //   `)
  // }

  public async getBridgeForTokenPair(
    l1Token: AddressLike,
    l2Token: AddressLike
  ): Promise<IBridgeAdapter> {
    const bridges: IBridgeAdapter[] = []
    for (const bridge of Object.values(this.bridges)) {
      if (await bridge.supportsTokenPair(l1Token, l2Token)) {
        bridges.push(bridge)
      }
    }

    if (bridges.length === 0) {
      throw new Error(`no supported bridge for token pair`)
    }

    if (bridges.length > 1) {
      throw new Error(`found more than one bridge for token pair`)
    }

    return bridges[0]
  }

  public async getDepositsByAddress(
    address: AddressLike,
    opts: {
      fromBlock?: BlockTag
      toBlock?: BlockTag
    } = {}
  ): Promise<TokenBridgeMessage[]> {
    return (
      await Promise.all(
        Object.values(this.bridges).map(async (bridge) => {
          return bridge.getDepositsByAddress(address, opts)
        })
      )
    )
      .reduce((acc, val) => {
        return acc.concat(val)
      }, [])
      .sort((a, b) => {
        // Sort descending by block number
        return b.blockNumber - a.blockNumber
      })
  }

  public async getWithdrawalsByAddress(
    address: AddressLike,
    opts: {
      fromBlock?: BlockTag
      toBlock?: BlockTag
    } = {}
  ): Promise<TokenBridgeMessage[]> {
    return (
      await Promise.all(
        Object.values(this.bridges).map(async (bridge) => {
          return bridge.getWithdrawalsByAddress(address, opts)
        })
      )
    )
      .reduce((acc, val) => {
        return acc.concat(val)
      }, [])
      .sort((a, b) => {
        // Sort descending by block number
        return b.blockNumber - a.blockNumber
      })
  }

  public async toCrossChainMessage(
    message: MessageLike
  ): Promise<CrossChainMessage> {
    // TODO: Convert these checks into proper type checks.
    if ((message as CrossChainMessage).message) {
      return message as CrossChainMessage
    } else if (
      (message as TokenBridgeMessage).l1Token &&
      (message as TokenBridgeMessage).l2Token &&
      (message as TokenBridgeMessage).transactionHash
    ) {
      const messages = await this.getMessagesByTransaction(
        (message as TokenBridgeMessage).transactionHash
      )

      // The `messages` object corresponds to a list of SentMessage events that were triggered by
      // the same transaction. We want to find the specific SentMessage event that corresponds to
      // the TokenBridgeMessage (either a ETHDepositInitiated, ERC20DepositInitiated, or
      // WithdrawalInitiated event). We expect the behavior of bridge contracts to be that these
      // TokenBridgeMessage events are triggered and then a SentMessage event is triggered. Our
      // goal here is therefore to find the first SentMessage event that comes after the input
      // event.
      const found = messages
        .sort((a, b) => {
          // Sort all messages in ascending order by log index.
          return a.logIndex - b.logIndex
        })
        .find((m) => {
          return m.logIndex > (message as TokenBridgeMessage).logIndex
        })

      if (!found) {
        throw new Error(`could not find SentMessage event for message`)
      }

      return found
    } else {
      // TODO: Explicit TransactionLike check and throw if not TransactionLike
      const messages = await this.getMessagesByTransaction(
        message as TransactionLike
      )

      // We only want to treat TransactionLike objects as MessageLike if they only emit a single
      // message (very common). It's unintuitive to treat a TransactionLike as a MessageLike if
      // they emit more than one message (which message do you pick?), so we throw an error.
      if (messages.length !== 1) {
        throw new Error(`expected 1 message, got ${messages.length}`)
      }

      return messages[0]
    }
  }

  public async getMessageReceipt(
    message: MessageLike
  ): Promise<MessageReceipt> {
    const resolved = await this.toCrossChainMessage(message)
    const messageHash = hashCrossDomainMessage(
      resolved.messageNonce,
      resolved.sender,
      resolved.target,
      resolved.value,
      resolved.minGasLimit,
      resolved.message
    )

    // Here we want the messenger that will receive the message, not the one that sent it.
    const messenger =
      resolved.direction === MessageDirection.L1_TO_L2
        ? this.contracts.l2.L2CrossDomainMessenger
        : this.contracts.l1.L1CrossDomainMessenger

    const relayedMessageEvents = await messenger.queryFilter(
      messenger.filters.RelayedMessage(messageHash)
    )

    // Great, we found the message. Convert it into a transaction receipt.
    if (relayedMessageEvents.length === 1) {
      return {
        receiptStatus: MessageReceiptStatus.RELAYED_SUCCEEDED,
        transactionReceipt:
          await relayedMessageEvents[0].getTransactionReceipt(),
      }
    } else if (relayedMessageEvents.length > 1) {
      // Should never happen!
      throw new Error(`multiple successful relays for message`)
    }

    // We didn't find a transaction that relayed the message. We now attempt to find
    // FailedRelayedMessage events instead.
    const failedRelayedMessageEvents = await messenger.queryFilter(
      messenger.filters.FailedRelayedMessage(messageHash)
    )

    // A transaction can fail to be relayed multiple times. We'll always return the last
    // transaction that attempted to relay the message.
    // TODO: Is this the best way to handle this?
    if (failedRelayedMessageEvents.length > 0) {
      return {
        receiptStatus: MessageReceiptStatus.RELAYED_FAILED,
        transactionReceipt: await failedRelayedMessageEvents[
          failedRelayedMessageEvents.length - 1
        ].getTransactionReceipt(),
      }
    }

    // TODO: If the user doesn't provide enough gas then there's a chance that FailedRelayedMessage
    // will never be triggered. We should probably fix this at the contract level by requiring a
    // minimum amount of input gas and designing the contracts such that the gas will always be
    // enough to trigger the event. However, for now we need a temporary way to find L1 => L2
    // transactions that fail but don't alert us because they didn't provide enough gas.
    // TODO: Talk with the systems and protocol team about coordinating a hard fork that fixes this
    // on both L1 and L2.

    // Just return null if we didn't find a receipt. Slightly nicer than throwing an error.
    return null
  }

  public async waitForMessageReceipt(
    message: MessageLike,
    opts: {
      confirmations?: number
      pollIntervalMs?: number
      timeoutMs?: number
    } = {}
  ): Promise<MessageReceipt> {
    // Resolving once up-front is slightly more efficient.
    const resolved = await this.toCrossChainMessage(message)

    let totalTimeMs = 0
    while (totalTimeMs < (opts.timeoutMs || Infinity)) {
      const tick = Date.now()
      const receipt = await this.getMessageReceipt(resolved)
      if (receipt !== null) {
        return receipt
      } else {
        await sleep(opts.pollIntervalMs || 4000)
        totalTimeMs += Date.now() - tick
      }
    }

    throw new Error(`timed out waiting for message receipt`)
  }

  public async estimateL2MessageGasLimit(
    message: MessageRequestLike,
    opts?: {
      bufferPercent?: number
      from?: string
    }
  ): Promise<BigNumber> {
    let resolved: CrossChainMessage | CrossChainMessageRequest
    let from: string
    if ((message as CrossChainMessage).messageNonce === undefined) {
      resolved = message as CrossChainMessageRequest
      from = opts?.from
    } else {
      resolved = await this.toCrossChainMessage(message as MessageLike)
      from = opts?.from || (resolved as CrossChainMessage).sender
    }

    // L2 message gas estimation is only used for L1 => L2 messages.
    if (resolved.direction === MessageDirection.L2_TO_L1) {
      throw new Error(`cannot estimate gas limit for L2 => L1 message`)
    }

    const estimate = await this.l2Provider.estimateGas({
      from,
      to: resolved.target,
      data: resolved.message,
    })

    // Return the estimate plus a buffer of 20% just in case.
    const bufferPercent = opts?.bufferPercent || 20
    return estimate.mul(100 + bufferPercent).div(100)
  }

  public async getChallengePeriodSeconds(): Promise<number> {
    const challengePeriod =
      await this.contracts.l1.OptimismPortal.FINALIZATION_PERIOD_SECONDS()
    return challengePeriod.toNumber()
  }

  public async getMessageBedrockOutput(
    message: MessageLike
  ): Promise<BedrockOutputData | null> {
    const resolved = await this.toCrossChainMessage(message)

    // Outputs are only a thing for L2 to L1 messages.
    if (resolved.direction === MessageDirection.L1_TO_L2) {
      throw new Error(`cannot get a state root for an L1 to L2 message`)
    }

    const l2OutputOracleParameters = await this.getL2OutputOracleParameters()

    // TODO: better way to do this
    let number =
      resolved.blockNumber - l2OutputOracleParameters.startingBlockNumber
    while (number % l2OutputOracleParameters.submissionInterval !== 0) {
      number++
    }

    // TODO: Handle old messages from before Bedrock upgrade.
    const events = await this.contracts.l1.L2OutputOracle.queryFilter(
      this.contracts.l1.L2OutputOracle.filters.OutputProposed(
        undefined,
        undefined,
        number
      )
    )

    if (events.length === 0) {
      return null
    }

    // Should not happen
    if (events.length > 1) {
      throw new Error(`multiple output roots found for message`)
    }

    return {
      outputRoot: events[0].args.l2Output,
      l1Timestamp: events[0].args.l1Timestamp.toNumber(),
      l2BlockNumber: events[0].args.l2BlockNumber.toNumber(),
    }
  }

  public async getBedrockMessageProof(
    message: MessageLike
  ): Promise<
    [BedrockCrossChainMessageProof, BedrockOutputData, CoreCrossChainMessage]
  > {
    const resolved = await this.toCrossChainMessage(message)
    if (resolved.direction === MessageDirection.L1_TO_L2) {
      throw new Error(`can only generate proofs for L2 to L1 messages`)
    }
    await sleep(15000)
    const output = await this.getMessageBedrockOutput(resolved)
    if (output === null) {
      throw new Error(`state root for message not yet published`)
    }

    const receipt = await this.l2Provider.getTransactionReceipt(
      resolved.transactionHash
    )

    interface WithdrawalEntry {
      withdrawalInitiated: any
      withdrawalInitiatedExtension1: any
    }

    // Handle multiple withdrawals in the same tx and be backwards
    // compatible without WithdrawalInitiatedExtension1
    const logs: Partial<{ number: WithdrawalEntry }> = {}
    for (const [i, log] of Object.entries(receipt.logs)) {
      if (log.address === predeploys.L2ToL1MessagePasser) {
        const decoded =
          this.contracts.l2.L2ToL1MessagePasser.interface.parseLog(log)
        // Find the withdrawal initiated events
        if (decoded.name === 'WithdrawalInitiated') {
          logs[log.logIndex] = {
            withdrawalInitiated: decoded.args,
            withdrawalInitiatedExtension1: null,
          }
          if (receipt.logs[i + 1]) {
            const next =
              this.contracts.l2.L2ToL1MessagePasser.interface.parseLog(
                receipt.logs[i + 1]
              )
            if (next.name === 'WithdrawalInitiatedExtension1') {
              logs[log.logIndex].withdrawalInitiatedExtension1 = next.args
            }
          }
        }
      }
    }

    // TODO(tynes): be able to handle transactions that do multiple withdrawals
    // in a single transaction. Right now just go for the first one.
    const withdrawal = Object.values(logs)[0]
    if (!withdrawal) {
      throw new Error(
        `Cannot find withdrawal logs for ${resolved.transactionHash}`
      )
    }

    const withdrawalHash = hashWithdrawal(
      withdrawal.withdrawalInitiated.nonce,
      withdrawal.withdrawalInitiated.sender,
      withdrawal.withdrawalInitiated.target,
      withdrawal.withdrawalInitiated.value,
      withdrawal.withdrawalInitiated.gasLimit,
      withdrawal.withdrawalInitiated.data
    )

    // Sanity check
    if (withdrawal.withdrawalInitiatedExtension1) {
      if (withdrawal.withdrawalInitiatedExtension1.hash !== withdrawalHash) {
        throw new Error(`Mismatched withdrawal hashes`)
      }
    }

    // TODO: turn into util
    const preimage = ethers.utils.defaultAbiCoder.encode(
      ['bytes32', 'uint256'],
      [withdrawalHash, ethers.constants.HashZero]
    )
    const isMessageSent =
      await this.contracts.l2.L2ToL1MessagePasser.sentMessages(withdrawalHash)

    if (!isMessageSent) {
      throw new Error(`Withdrawal not initiated on L2`)
    }

    const messageSlot = ethers.utils.keccak256(preimage)

    const stateTrieProof = await makeStateTrieProof(
      this.l2Provider as ethers.providers.JsonRpcProvider,
      output.l2BlockNumber,
      this.contracts.l2.L2ToL1MessagePasser.address,
      messageSlot
    )

    // Sanity check that the value is set to 1 in the state
    if (!stateTrieProof.storageValue.eq(1)) {
      throw new Error(`Withdrawal hash ${withdrawalHash} is not set in state`)
    }

    const block = await (
      this.l2Provider as ethers.providers.JsonRpcProvider
    ).send('eth_getBlockByNumber', [
      toRpcHexString(output.l2BlockNumber),
      false,
    ])

    return [
      {
        outputRootProof: {
          // TODO: Handle multiple versions in the future
          version: ethers.constants.HashZero,
          stateRoot: block.stateRoot,
          withdrawerStorageRoot: stateTrieProof.storageRoot,
          latestBlockhash: block.hash,
        },
        withdrawalProof: ethers.utils.RLP.encode(stateTrieProof.storageProof),
      },
      output,
      // TODO(tynes): use better type, typechain?
      {
        messageNonce: withdrawal.withdrawalInitiated.nonce,
        sender: withdrawal.withdrawalInitiated.sender,
        target: withdrawal.withdrawalInitiated.target,
        value: withdrawal.withdrawalInitiated.value,
        minGasLimit: withdrawal.withdrawalInitiated.gasLimit,
        message: withdrawal.withdrawalInitiated.data,
      },
    ]
  }

  public async sendMessage(
    message: CrossChainMessageRequest,
    opts?: {
      signer?: Signer
      l2GasLimit?: NumberLike
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    const tx = await this.populateTransaction.sendMessage(message, opts)
    if (message.direction === MessageDirection.L1_TO_L2) {
      return (opts?.signer || this.l1Signer).sendTransaction(tx)
    } else {
      return (opts?.signer || this.l2Signer).sendTransaction(tx)
    }
  }

  public async resendMessage(
    message: MessageLike,
    messageGasLimit: NumberLike,
    opts?: {
      signer?: Signer
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l1Signer).sendTransaction(
      await this.populateTransaction.resendMessage(
        message,
        messageGasLimit,
        opts
      )
    )
  }

  public async finalizeMessage(
    message: MessageLike,
    opts?: {
      signer?: Signer
      overrides?: PayableOverrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l1Signer).sendTransaction(
      await this.populateTransaction.finalizeMessage(message, opts)
    )
  }

  public async depositETH(
    amount: NumberLike,
    opts?: {
      recipient?: AddressLike
      signer?: Signer
      l2GasLimit?: NumberLike
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l1Signer).sendTransaction(
      await this.populateTransaction.depositETH(amount, opts)
    )
  }

  public async withdrawETH(
    amount: NumberLike,
    opts?: {
      recipient?: AddressLike
      signer?: Signer
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l2Signer).sendTransaction(
      await this.populateTransaction.withdrawETH(amount, opts)
    )
  }

  public async approval(
    l1Token: AddressLike,
    l2Token: AddressLike,
    opts?: {
      signer?: Signer
    }
  ): Promise<BigNumber> {
    const bridge = await this.getBridgeForTokenPair(l1Token, l2Token)
    return bridge.approval(l1Token, l2Token, opts?.signer || this.l1Signer)
  }

  public async approveERC20(
    l1Token: AddressLike,
    l2Token: AddressLike,
    amount: NumberLike,
    opts?: {
      signer?: Signer
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l1Signer).sendTransaction(
      await this.populateTransaction.approveERC20(
        l1Token,
        l2Token,
        amount,
        opts
      )
    )
  }

  public async depositERC20(
    l1Token: AddressLike,
    l2Token: AddressLike,
    amount: NumberLike,
    opts?: {
      recipient?: AddressLike
      signer?: Signer
      l2GasLimit?: NumberLike
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l1Signer).sendTransaction(
      await this.populateTransaction.depositERC20(
        l1Token,
        l2Token,
        amount,
        opts
      )
    )
  }

  public async withdrawERC20(
    l1Token: AddressLike,
    l2Token: AddressLike,
    amount: NumberLike,
    opts?: {
      recipient?: AddressLike
      signer?: Signer
      overrides?: Overrides
    }
  ): Promise<TransactionResponse> {
    return (opts?.signer || this.l2Signer).sendTransaction(
      await this.populateTransaction.withdrawERC20(
        l1Token,
        l2Token,
        amount,
        opts
      )
    )
  }

  populateTransaction = {
    sendMessage: async (
      message: CrossChainMessageRequest,
      opts?: {
        l2GasLimit?: NumberLike
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      if (message.direction === MessageDirection.L1_TO_L2) {
        return this.contracts.l1.L1CrossDomainMessenger.populateTransaction.sendMessage(
          message.target,
          message.message,
          opts?.l2GasLimit || (await this.estimateL2MessageGasLimit(message)),
          opts?.overrides || {}
        )
      } else {
        return this.contracts.l2.L2CrossDomainMessenger.populateTransaction.sendMessage(
          message.target,
          message.message,
          0, // Gas limit goes unused when sending from L2 to L1
          opts?.overrides || {}
        )
      }
    },

    resendMessage: async (
      message: MessageLike,
      messageGasLimit: NumberLike,
      opts?: {
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      const resolved = await this.toCrossChainMessage(message)
      if (resolved.direction === MessageDirection.L2_TO_L1) {
        throw new Error(`cannot resend L2 to L1 message`)
      }

      if (this.bedrock) {
        return this.populateTransaction.finalizeMessage(resolved, {
          ...(opts || {}),
          overrides: {
            ...opts?.overrides,
            gasLimit: messageGasLimit,
          },
        })
      } else {
        const legacyL1XDM = new ethers.Contract(
          this.contracts.l1.L1CrossDomainMessenger.address,
          getContractInterface('L1CrossDomainMessenger'),
          this.l1SignerOrProvider
        )
        return legacyL1XDM.populateTransaction.replayMessage(
          resolved.target,
          resolved.sender,
          resolved.message,
          resolved.messageNonce,
          resolved.minGasLimit,
          messageGasLimit,
          opts?.overrides || {}
        )
      }
    },

    finalizeMessage: async (
      message: MessageLike,
      opts?: {
        overrides?: PayableOverrides
      }
    ): Promise<TransactionRequest> => {
      const resolved = await this.toCrossChainMessage(message)
      if (resolved.direction === MessageDirection.L1_TO_L2) {
        throw new Error(`cannot finalize L1 to L2 message`)
      }

      if (this.bedrock) {
        const [proof, output, withdrawalTx] = await this.getBedrockMessageProof(
          message
        )

        return this.contracts.l1.OptimismPortal.populateTransaction.finalizeWithdrawalTransaction(
          [
            withdrawalTx.messageNonce,
            withdrawalTx.sender,
            withdrawalTx.target,
            withdrawalTx.value,
            withdrawalTx.minGasLimit,
            withdrawalTx.message,
          ],
          output.l2BlockNumber,
          [
            proof.outputRootProof.version,
            proof.outputRootProof.stateRoot,
            proof.outputRootProof.withdrawerStorageRoot,
            proof.outputRootProof.latestBlockhash,
          ],
          proof.withdrawalProof,
          opts?.overrides || {}
        )
      }
    },

    depositETH: async (
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        l2GasLimit?: NumberLike
        overrides?: PayableOverrides
      }
    ): Promise<TransactionRequest> => {
      return this.bridges.ETH.populateTransaction.deposit(
        ethers.constants.AddressZero,
        predeploys.OVM_ETH,
        amount,
        opts
      )
    },

    withdrawETH: async (
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      return this.bridges.ETH.populateTransaction.withdraw(
        ethers.constants.AddressZero,
        predeploys.OVM_ETH,
        amount,
        opts
      )
    },

    approveERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      const bridge = await this.getBridgeForTokenPair(l1Token, l2Token)
      return bridge.populateTransaction.approve(l1Token, l2Token, amount, opts)
    },

    depositERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        l2GasLimit?: NumberLike
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      const bridge = await this.getBridgeForTokenPair(l1Token, l2Token)
      return bridge.populateTransaction.deposit(l1Token, l2Token, amount, opts)
    },

    withdrawERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        overrides?: Overrides
      }
    ): Promise<TransactionRequest> => {
      const bridge = await this.getBridgeForTokenPair(l1Token, l2Token)
      return bridge.populateTransaction.withdraw(l1Token, l2Token, amount, opts)
    },
  }

  estimateGas = {
    sendMessage: async (
      message: CrossChainMessageRequest,
      opts?: {
        l2GasLimit?: NumberLike
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      const tx = await this.populateTransaction.sendMessage(message, opts)
      if (message.direction === MessageDirection.L1_TO_L2) {
        return this.l1Provider.estimateGas(tx)
      } else {
        return this.l2Provider.estimateGas(tx)
      }
    },

    resendMessage: async (
      message: MessageLike,
      messageGasLimit: NumberLike,
      opts?: {
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l1Provider.estimateGas(
        await this.populateTransaction.resendMessage(
          message,
          messageGasLimit,
          opts
        )
      )
    },

    finalizeMessage: async (
      message: MessageLike,
      opts?: {
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l1Provider.estimateGas(
        await this.populateTransaction.finalizeMessage(message, opts)
      )
    },

    depositETH: async (
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        l2GasLimit?: NumberLike
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l1Provider.estimateGas(
        await this.populateTransaction.depositETH(amount, opts)
      )
    },

    withdrawETH: async (
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l2Provider.estimateGas(
        await this.populateTransaction.withdrawETH(amount, opts)
      )
    },

    approveERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l1Provider.estimateGas(
        await this.populateTransaction.approveERC20(
          l1Token,
          l2Token,
          amount,
          opts
        )
      )
    },

    depositERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        l2GasLimit?: NumberLike
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l1Provider.estimateGas(
        await this.populateTransaction.depositERC20(
          l1Token,
          l2Token,
          amount,
          opts
        )
      )
    },

    withdrawERC20: async (
      l1Token: AddressLike,
      l2Token: AddressLike,
      amount: NumberLike,
      opts?: {
        recipient?: AddressLike
        overrides?: CallOverrides
      }
    ): Promise<BigNumber> => {
      return this.l2Provider.estimateGas(
        await this.populateTransaction.withdrawERC20(
          l1Token,
          l2Token,
          amount,
          opts
        )
      )
    },
  }
}
