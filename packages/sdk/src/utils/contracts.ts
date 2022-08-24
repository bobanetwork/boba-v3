import { ethers, Contract } from 'ethers'
import { getContractInterface } from '@eth-optimism/contracts-bedrock/dist/contract-defs'

import { toAddress } from './coercion'
import { DeepPartial } from './type-utils'
import {
  OEContracts,
  OEL1Contracts,
  OEL2Contracts,
  OEContractsLike,
  OEL2ContractsLike,
  AddressLike,
  BridgeAdapters,
  BridgeAdapterData,
  ICrossChainMessenger,
  L2ChainID,
} from '../interfaces'
import { StandardBridgeAdapter, ETHBridgeAdapter } from '../adapters'
import { predeploys } from '../cross-chain-messenger'

/**
 * Full list of default L2 contract addresses.
 * TODO(tynes): migrate to predeploys from contracts-bedrock
 */
export const DEFAULT_L2_CONTRACT_ADDRESSES: OEL2ContractsLike = {
  L2CrossDomainMessenger: predeploys.L2CrossDomainMessenger,
  L2ToL1MessagePasser: predeploys.L2ToL1MessagePasser,
  L2StandardBridge: predeploys.L2StandardBridge,
  L1BlockNumber: predeploys.L1BlockNumber,
  // DeployerWhitelist: predeploys.DeployerWhitelist,
  LegacyERC20ETH: predeploys.OVM_ETH,
  GasPriceOracle: predeploys.GasPriceOracle,
  //SequencerFeeVault: predeploys.SequencerFeeVault,
}

/**
 * We've changed some contract names in this SDK to be a bit nicer. Here we remap these nicer names
 * back to the original contract names so we can look them up.
 */
const NAME_REMAPPING = {
  AddressManager: 'AddressManager' as const,
  OVM_L1BlockNumber: 'L1BlockNumber' as const,
  L1BlockNumber: 'L1BlockNumber' as const,
  WETH: 'WETH9' as const,
}

/**
 * Mapping of L1 chain IDs to the appropriate contract addresses for the OE deployments to the
 * given network. Simplifies the process of getting the correct contract addresses for a given
 * contract name.
 */
export const CONTRACT_ADDRESSES: {
  [ChainID in L2ChainID]: OEContractsLike
} = {
  [L2ChainID.OPTIMISM_BEDROCK_LOCAL_DEVNET]: {
    l1: {
      AddressManager: '0x5FbDB2315678afecb367f032d93F642f64180aa3' as const,
      L1CrossDomainMessenger:
        '0x0165878A594ca255338adfa4d48449f69242Eb8F' as const,
      L1StandardBridge: '0x8A791620dd6260079BF849Dc5567aDC3F2FdC318' as const,
      //BondManager: '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707' as const,
      OptimismPortal: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9' as const,
      L2OutputOracle: '0x5FbDB2315678afecb367f032d93F642f64180aa3' as const,
    },
    l2: DEFAULT_L2_CONTRACT_ADDRESSES,
  },
}

/**
 * Returns an ethers.Contract object for the given name, connected to the appropriate address for
 * the given L2 chain ID. Users can also provide a custom address to connect the contract to
 * instead. If the chain ID is not known then the user MUST provide a custom address or this
 * function will throw an error.
 *
 * @param contractName Name of the contract to connect to.
 * @param l2ChainId Chain ID for the L2 network.
 * @param opts Additional options for connecting to the contract.
 * @param opts.address Custom address to connect to the contract.
 * @param opts.signerOrProvider Signer or provider to connect to the contract.
 * @returns An ethers.Contract object connected to the appropriate address and interface.
 */
export const getOEContract = (
  contractName: keyof OEL1Contracts | keyof OEL2Contracts,
  l2ChainId: number,
  opts: {
    address?: AddressLike
    signerOrProvider?: ethers.Signer | ethers.providers.Provider
  } = {}
): Contract => {
  const addresses = CONTRACT_ADDRESSES[l2ChainId]
  if (addresses === undefined && opts.address === undefined) {
    throw new Error(
      `cannot get contract ${contractName} for unknown L2 chain ID ${l2ChainId}, you must provide an address`
    )
  }

  // Bedrock interfaces are backwards compatible. We can prefer Bedrock interfaces over legacy
  // interfaces if they exist.
  const name = NAME_REMAPPING[contractName] || contractName
  const iface: ethers.utils.Interface = getContractInterface(name)

  return new Contract(
    toAddress(
      opts.address || addresses.l1[contractName] || addresses.l2[contractName]
    ),
    iface,
    opts.signerOrProvider
  )
}

/**
 * Automatically connects to all contract addresses, both L1 and L2, for the given L2 chain ID. The
 * user can provide custom contract address overrides for L1 or L2 contracts. If the given chain ID
 * is not known then the user MUST provide custom contract addresses for ALL L1 contracts or this
 * function will throw an error.
 *
 * @param l2ChainId Chain ID for the L2 network.
 * @param opts Additional options for connecting to the contracts.
 * @param opts.l1SignerOrProvider: Signer or provider to connect to the L1 contracts.
 * @param opts.l2SignerOrProvider: Signer or provider to connect to the L2 contracts.
 * @param opts.overrides Custom contract address overrides for L1 or L2 contracts.
 * @returns An object containing ethers.Contract objects connected to the appropriate addresses on
 * both L1 and L2.
 */
export const getAllOEContracts = (
  l2ChainId: number,
  opts: {
    l1SignerOrProvider?: ethers.Signer | ethers.providers.Provider
    l2SignerOrProvider?: ethers.Signer | ethers.providers.Provider
    overrides?: DeepPartial<OEContractsLike>
  } = {}
): OEContracts => {
  const addresses = CONTRACT_ADDRESSES[l2ChainId] || {
    l1: {
      AddressManager: undefined,
      L1CrossDomainMessenger: undefined,
      L1StandardBridge: undefined,
      StateCommitmentChain: undefined,
      CanonicalTransactionChain: undefined,
      BondManager: undefined,
      OptimismPortal: undefined,
      L2OutputOracle: undefined,
    },
    l2: DEFAULT_L2_CONTRACT_ADDRESSES,
  }

  // Attach all L1 contracts.
  const l1Contracts = {} as OEL1Contracts
  for (const [contractName, contractAddress] of Object.entries(addresses.l1)) {
    l1Contracts[contractName] = getOEContract(
      contractName as keyof OEL1Contracts,
      l2ChainId,
      {
        address: opts.overrides?.l1?.[contractName] || contractAddress,
        signerOrProvider: opts.l1SignerOrProvider,
      }
    )
  }

  // Attach all L2 contracts.
  const l2Contracts = {} as OEL2Contracts
  for (const [contractName, contractAddress] of Object.entries(addresses.l2)) {
    l2Contracts[contractName] = getOEContract(
      contractName as keyof OEL2Contracts,
      l2ChainId,
      {
        address: opts.overrides?.l2?.[contractName] || contractAddress,
        signerOrProvider: opts.l2SignerOrProvider,
      }
    )
  }

  return {
    l1: l1Contracts,
    l2: l2Contracts,
  }
}

/**
 * Gets a series of bridge adapters for the given L2 chain ID.
 *
 * @param l2ChainId Chain ID for the L2 network.
 * @param messenger Cross chain messenger to connect to the bridge adapters
 * @param opts Additional options for connecting to the custom bridges.
 * @param opts.overrides Custom bridge adapters.
 * @returns An object containing all bridge adapters
 */
export const getBridgeAdapters = (
  l2ChainId: number,
  messenger: ICrossChainMessenger,
  opts?: {
    overrides?: BridgeAdapterData
  }
): BridgeAdapters => {
  const adapterData: BridgeAdapterData = {
    ...(CONTRACT_ADDRESSES[l2ChainId]
      ? {
          Standard: {
            Adapter: StandardBridgeAdapter,
            l1Bridge: CONTRACT_ADDRESSES[l2ChainId].l1.L1StandardBridge,
            l2Bridge: predeploys.L2StandardBridge,
          },
          ETH: {
            Adapter: ETHBridgeAdapter,
            l1Bridge: CONTRACT_ADDRESSES[l2ChainId].l1.L1StandardBridge,
            l2Bridge: predeploys.L2StandardBridge,
          },
        }
      : {}),
    ...{},
    ...(opts?.overrides || {}),
  }

  const adapters: BridgeAdapters = {}
  for (const [bridgeName, bridgeData] of Object.entries(adapterData)) {
    adapters[bridgeName] = new bridgeData.Adapter({
      messenger,
      l1Bridge: bridgeData.l1Bridge,
      l2Bridge: bridgeData.l2Bridge,
    })
  }

  return adapters
}
