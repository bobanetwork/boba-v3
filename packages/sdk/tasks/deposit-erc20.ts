import { task, types } from 'hardhat/config'
import { HardhatRuntimeEnvironment } from 'hardhat/types'
import '@nomiclabs/hardhat-ethers'
import 'hardhat-deploy'
import { Event, Contract, Wallet, providers, utils } from 'ethers'

import {
  CrossChainMessenger,
  StandardBridgeAdapter,
  MessageStatus,
} from '../src'
import { predeploys } from './deposit-eth'

const deployWETH9 = async (
  hre: HardhatRuntimeEnvironment,
  wrap: boolean
): Promise<Contract> => {
  const signers = await hre.ethers.getSigners()
  const signer = signers[0]

  const Artifact__WETH9 = await hre.deployments.getArtifact('WETH9')
  const Factory__WETH9 = new hre.ethers.ContractFactory(
    Artifact__WETH9.abi,
    Artifact__WETH9.bytecode,
    signer
  )

  const WETH9 = await Factory__WETH9.deploy()
  await WETH9.deployTransaction.wait()

  if (wrap) {
    const deposit = await signer.sendTransaction({
      value: utils.parseEther('1'),
      to: WETH9.address,
    })
    await deposit.wait()
  }

  return WETH9
}

const createOptimismMintableERC20 = async (
  hre: HardhatRuntimeEnvironment,
  L1ERC20: Contract,
  l2Signer: Wallet
): Promise<Contract> => {
  const Deployment__OptimismMintableERC20TokenFactory =
    await hre.deployments.get('OptimismMintableERC20Factory')

  const Artifact__OptimismMintableERC20Token =
    await hre.deployments.getArtifact('OptimismMintableERC20')

  const OptimismMintableERC20TokenFactory = await hre.ethers.getContractAt(
    Deployment__OptimismMintableERC20TokenFactory.abi,
    predeploys.L2StandardTokenFactory,
    l2Signer
  )

  const name = await L1ERC20.name()
  const symbol = await L1ERC20.symbol()

  const tx =
    await OptimismMintableERC20TokenFactory.createOptimismMintableERC20(
      L1ERC20.address,
      `L2 ${name}`,
      `L2-${symbol}`
    )

  const receipt = await tx.wait()
  const event = receipt.events.find(
    (e: Event) => e.event === 'OptimismMintableERC20Created'
  )

  if (!event) {
    throw new Error('Unable to find OptimismMintableERC20Created event')
  }

  // TODO(tynes): may need to be updated based on
  // https://github.com/ethereum-optimism/optimism/pull/3104
  const l2WethAddress = event.args.remoteToken
  console.log(`Deployed to ${l2WethAddress}`)

  const contract = new Contract(
    l2WethAddress,
    Artifact__OptimismMintableERC20Token.abi,
    l2Signer
  )

  return contract
}

// TODO(tynes): this task could be modularized in the future
// so that it can deposit an arbitrary token. Right now it
// deploys a WETH9 contract, mints some WETH9 and then
// deposits that into L2 through the StandardBridge.
task('deposit-erc20', 'Deposits WETH9 onto L2.')
  .addParam(
    'l2ProviderUrl',
    'L2 provider URL.',
    'http://localhost:9545',
    types.string
  )
  .addParam(
    'opNodeProviderUrl',
    'op-node provider URL',
    'http://localhost:7545',
    types.string
  )
  .setAction(async (args, hre) => {
    const signers = await hre.ethers.getSigners()
    if (signers.length === 0) {
      throw new Error('No configured signers')
    }
    // Use the first configured signer for simplicity
    const signer = signers[0]
    const address = await signer.getAddress()
    console.log(`Using signer ${address}`)

    // Ensure that the signer has a balance before trying to
    // do anything
    const balance = await signer.getBalance()
    if (balance.eq(0)) {
      throw new Error('Signer has no balance')
    }

    const l2Provider = new providers.StaticJsonRpcProvider(args.l2ProviderUrl)

    const l2Signer = new hre.ethers.Wallet(
      hre.network.config.accounts[0],
      l2Provider
    )

    const Deployment__L2OutputOracleProxy = await hre.deployments.get(
      'L2OutputOracleProxy'
    )

    const Artifact__L2ToL1MessagePasser = await hre.deployments.getArtifact(
      'L2ToL1MessagePasser'
    )

    const Artifact__L2CrossDomainMessenger = await hre.deployments.getArtifact(
      'L2CrossDomainMessenger'
    )

    const Artifact__L2StandardBridge = await hre.deployments.getArtifact(
      'L2StandardBridge'
    )

    const Deployment__OptimismPortal = await hre.deployments.get(
      'OptimismPortal'
    )

    const Deployment__OptimismPortalProxy = await hre.deployments.get(
      'OptimismPortalProxy'
    )

    const Deployment__L1StandardBridgeProxy = await hre.deployments.get(
      'L1StandardBridgeProxy'
    )

    const Deployment__L1CrossDomainMessenger = await hre.deployments.get(
      'L1CrossDomainMessenger'
    )

    const Deployment__L1CrossDomainMessengerProxy = await hre.deployments.get(
      'L1CrossDomainMessengerProxy'
    )

    const Deployment__L1StandardBridge = await hre.deployments.get(
      'L1StandardBridge'
    )

    const OptimismPortal = new hre.ethers.Contract(
      Deployment__OptimismPortalProxy.address,
      Deployment__OptimismPortal.abi,
      signer
    )

    const L1CrossDomainMessenger = new hre.ethers.Contract(
      Deployment__L1CrossDomainMessengerProxy.address,
      Deployment__L1CrossDomainMessenger.abi,
      signer
    )

    const L1StandardBridge = new hre.ethers.Contract(
      Deployment__L1StandardBridgeProxy.address,
      Deployment__L1StandardBridge.abi,
      signer
    )

    const L2ToL1MessagePasser = new hre.ethers.Contract(
      predeploys.L2ToL1MessagePasser,
      Artifact__L2ToL1MessagePasser.abi
    )

    const L2CrossDomainMessenger = new hre.ethers.Contract(
      predeploys.L2CrossDomainMessenger,
      Artifact__L2CrossDomainMessenger.abi
    )

    const L2StandardBridge = new hre.ethers.Contract(
      predeploys.L2StandardBridge,
      Artifact__L2StandardBridge.abi
    )

    const messenger = new CrossChainMessenger({
      l1SignerOrProvider: signer,
      l2SignerOrProvider: l2Signer,
      l1ChainId: await signer.getChainId(),
      l2ChainId: await l2Signer.getChainId(),
      bridges: {
        Standard: {
          Adapter: StandardBridgeAdapter,
          l1Bridge: Deployment__L1StandardBridgeProxy.address,
          l2Bridge: predeploys.L2StandardBridge,
        },
      },
      contracts: {
        l1: {
          L1StandardBridge: Deployment__L1StandardBridgeProxy.address,
          L1CrossDomainMessenger:
            Deployment__L1CrossDomainMessengerProxy.address,
          L2OutputOracle: Deployment__L2OutputOracleProxy.address,
          OptimismPortal: Deployment__OptimismPortalProxy.address,
        },
      },
      bedrock: true,
    })

    console.log('Deploying WETH9 to L1')
    const WETH9 = await deployWETH9(hre, true)
    console.log(`Deployed to ${WETH9.address}`)

    console.log('Creating L2 WETH9')
    const OptimismMintableERC20 = await createOptimismMintableERC20(
      hre,
      WETH9,
      l2Signer
    )

    console.log(`Approving WETH9 for deposit`)
    const approvalTx = await messenger.approveERC20(
      WETH9.address,
      OptimismMintableERC20.address,
      hre.ethers.constants.MaxUint256
    )
    await approvalTx.wait()
    console.log('WETH9 approved')

    console.log('Depositing WETH9 to L2')
    const depositTx = await messenger.depositERC20(
      WETH9.address,
      OptimismMintableERC20.address,
      utils.parseEther('1')
    )
    await depositTx.wait()
    console.log(`ERC20 deposited - ${depositTx.hash}`)

    const messageReceipt = await messenger.waitForMessageReceipt(depositTx)
    if (messageReceipt.receiptStatus !== 1) {
      throw new Error('deposit failed')
    }

    const l2Balance = await OptimismMintableERC20.balanceOf(address)
    if (l2Balance.lt(utils.parseEther('1'))) {
      throw new Error('bad deposit')
    }
    console.log(
      `Deposit success - ${messageReceipt.transactionReceipt.transactionHash}`
    )

    console.log('Starting withdrawal')
    const preBalance = await WETH9.balanceOf(signer.address)
    const withdraw = await messenger.withdrawERC20(
      WETH9.address,
      OptimismMintableERC20.address,
      utils.parseEther('1')
    )
    const withdrawalReceipt = await withdraw.wait()
    for (const log of withdrawalReceipt.logs) {
      switch (log.address) {
        case L2ToL1MessagePasser.address: {
          const parsed = L2ToL1MessagePasser.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        case L2StandardBridge.address: {
          const parsed = L2StandardBridge.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        case L2CrossDomainMessenger.address: {
          const parsed = L2CrossDomainMessenger.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        default: {
          console.log(`Unknown log from ${log.address} - ${log.topics[0]}`)
        }
      }
    }

    // setInterval(async () => {
    //   const currentStatus = await messenger.getMessageStatus(withdraw)
    //   console.log(`Message status: ${MessageStatus[currentStatus]}`)
    // }, 3000)

    const now = Math.floor(Date.now() / 1000)

    // console.log('Waiting for message to be able to be relayed')
    // await messenger.waitForMessageStatus(
    //   withdraw,
    //   MessageStatus.READY_FOR_RELAY
    // )

    const finalize = await messenger.finalizeMessage(withdraw)
    const receipt = await finalize.wait()
    console.log(`Took ${Math.floor(Date.now() / 1000) - now} seconds`)

    for (const log of receipt.logs) {
      switch (log.address) {
        case OptimismPortal.address: {
          const parsed = OptimismPortal.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        case L1CrossDomainMessenger.address: {
          const parsed = L1CrossDomainMessenger.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        case L1StandardBridge.address: {
          const parsed = L1StandardBridge.interface.parseLog(log)
          console.log(`Log ${parsed.name} from ${log.address}`)
          console.log(parsed.args)
          console.log()
          break
        }
        default:
          console.log(
            `Unknown log emitted from ${log.address} - ${log.topics[0]}`
          )
      }
    }

    const postBalance = await WETH9.balanceOf(signer.address)

    const expectedBalance = preBalance.add(utils.parseEther('1'))
    if (!expectedBalance.eq(postBalance)) {
      throw new Error('Balance mismatch')
    }
    console.log('Withdrawal success')
  })
