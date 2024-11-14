// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "./ERC6956Base.sol";
import "./IERC6956AttestationLimited.sol";
import "./IERC6956Floatable.sol";
import "./IERC6956ValidAnchors.sol";

/**
 * @title ASSET-BOUND NFT implementation with all interfaces
 * @author Thomas Bergmueller (@tbergmueller)
 * @notice Extends ERC6956.sol with additional interfaces and functionality
 * 
 * @dev Error-codes
 * ERROR | Message
 * ------|-------------------------------------------------------------------
 * E1-20 | See ERC6956.sol
 * E21   | No permission to start floating
 * E22   | No permission to stop floating
 * E23   | allowFloating can only be called when changing floating state
 * E24   | No attested transfers left
 * E25   | data must contain merkle-proof
 * E26   | Anchor not valid
 * E27   | Updating attestedTransferLimit violates policy
 */
abstract contract ERC6956FullBase is ERC6956Base, IERC6956AttestationLimited, IERC6956Floatable, IERC6956ValidAnchors {

    /// ###############################################################################################################################
    /// ##############################################################################################  IERC6956AttestedTransferLimited
    /// ###############################################################################################################################

    /// @custom:storage-location erc7201:storage.ERC6956AttestedTransferLimitedStorage
    struct ERC6956AttestedTransferLimitedStorage {
        mapping(bytes32 => uint256) attestedTransferLimitByAnchor;
        uint256 globalAttestedTransferLimitByAnchor;
        AttestationLimitPolicy attestationLimitPolicy;
    }

     // keccak256(abi.encode(uint256(keccak256("storage.ERC6956AttestedTransferLimitedStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC6956AttestedTransferLimitedStorageLocation = 0xca942975389c3116dc1a6b8404d008d19456649fde423b108717763b926f5b00;

    function _getERC6956AttestedTransferLimitedStorage() private pure returns (ERC6956AttestedTransferLimitedStorage storage $) {
        assembly {
            $.slot := ERC6956AttestedTransferLimitedStorageLocation
        }
    }        

    function _requireValidLimitUpdate(uint256 oldValue, uint256 newValue) internal view {
        ERC6956AttestedTransferLimitedStorage storage $ = _getERC6956AttestedTransferLimitedStorage();

        if(newValue > oldValue) {
            require($.attestationLimitPolicy == AttestationLimitPolicy.FLEXIBLE || $.attestationLimitPolicy == AttestationLimitPolicy.INCREASE_ONLY, "ERC6956-E27");
        } else {
            require($.attestationLimitPolicy == AttestationLimitPolicy.FLEXIBLE || $.attestationLimitPolicy == AttestationLimitPolicy.DECREASE_ONLY, "ERC6956-E27");
        }
    }

    function attestationLimitPolicy() external view returns (AttestationLimitPolicy policy) {
        return _getERC6956AttestedTransferLimitedStorage().attestationLimitPolicy;
    }

    function globalAttestedTransferLimitByAnchor() external view returns (uint256) {
        return _getERC6956AttestedTransferLimitedStorage().globalAttestedTransferLimitByAnchor;
    }

        

    function updateGlobalAttestationLimit(uint256 _nrTransfers) 
        public 
        onlyMaintainer() 
    {
        ERC6956AttestedTransferLimitedStorage storage $ = _getERC6956AttestedTransferLimitedStorage();
       _requireValidLimitUpdate($.globalAttestedTransferLimitByAnchor, _nrTransfers);
       $.globalAttestedTransferLimitByAnchor = _nrTransfers;
       emit GlobalAttestationLimitUpdate(_nrTransfers, msg.sender);
    }

    function updateAttestationLimit(bytes32 anchor, uint256 _nrTransfers) 
        public 
        onlyMaintainer() 
    {
        ERC6956AttestedTransferLimitedStorage storage $ = _getERC6956AttestedTransferLimitedStorage();
       uint256 currentLimit = attestationLimit(anchor);
       _requireValidLimitUpdate(currentLimit, _nrTransfers);
       $.attestedTransferLimitByAnchor[anchor] = _nrTransfers;
       emit AttestationLimitUpdate(anchor, tokenByAnchor(anchor), _nrTransfers, msg.sender);
    }

    function attestationLimit(bytes32 anchor) public view returns (uint256 limit) {
        ERC6956AttestedTransferLimitedStorage storage $ = _getERC6956AttestedTransferLimitedStorage();
        if($.attestedTransferLimitByAnchor[anchor] > 0) { // Per anchor overwrites always, even if smaller than globalAttestedTransferLimit
            return $.attestedTransferLimitByAnchor[anchor];
        } 
        return $.globalAttestedTransferLimitByAnchor;
    }

    function attestationUsagesLeft(bytes32 anchor) public view returns (uint256 nrTransfersLeft) {
        // FIXME panics when attestationsUsedByAnchor > attestedTransferLimit 
        // since this should never happen, maybe ok?
        return attestationLimit(anchor) - attestationsUsedByAnchor(anchor);
    }

    /// ###############################################################################################################################
    /// ##############################################################################################  FLOATABILITY
    /// ###############################################################################################################################

    /// @custom:storage-location erc7201:storage.ERC6956Floatable
    struct ERC6956FloatableStorage {
        Authorization floatStartAuthorization;
        Authorization floatStopAuthorization;
        mapping(bytes32 => FloatState) floatingStateByAnchor;
        bool allFloating;
    }

    // keccak256(abi.encode(uint256(keccak256("storage.ERC6956Floatable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC6956FloatableStorageLocation = 0xb2ced8677a980eaa76dba7a3407d1a216ce9390d904dea0c6e9a8ff38ef0fe00; 

    function _getERC6956FloatableStorage() private pure returns (ERC6956FloatableStorage storage $) {
        assembly {
            $.slot := ERC6956FloatableStorageLocation
        }
    }
    
    function updateFloatingAuthorization(Authorization startAuthorization, Authorization stopAuthorization) public
        onlyMaintainer() {
            ERC6956FloatableStorage storage $ = _getERC6956FloatableStorage();
            
            $.floatStartAuthorization = startAuthorization;
            $.floatStopAuthorization = stopAuthorization;
            emit FloatingAuthorizationChange(startAuthorization, stopAuthorization, msg.sender);
    }

    function floatAll(bool doFloatAll) public onlyMaintainer() {
        ERC6956FloatableStorage storage $ = _getERC6956FloatableStorage();
        require(doFloatAll != $.allFloating, "ERC6956-E23");
        $.allFloating = doFloatAll;
        emit FloatingAllStateChange(doFloatAll, msg.sender);
    }


    function _floating(bool defaultFloatState, FloatState anchorFloatState) internal pure returns (bool floats) {
        if(anchorFloatState == FloatState.Default) {
            return defaultFloatState;
        }
        return anchorFloatState == FloatState.Floating; 
    }

    function float(bytes32 anchor, FloatState newFloatState) public 
    {
        ERC6956FloatableStorage storage $ = _getERC6956FloatableStorage();
        bool currentFloatState = floating(anchor);
        bool willFloat = _floating($.allFloating, newFloatState);

        require(willFloat != currentFloatState, "ERC6956-E23");

        if(willFloat) {
            require(_roleBasedAuthorization(anchor, createAuthorizationMap($.floatStartAuthorization)), "ERC6956-E21");
        } else {
            require(_roleBasedAuthorization(anchor, createAuthorizationMap($.floatStopAuthorization)), "ERC6956-E22");
        }

        $.floatingStateByAnchor[anchor] = newFloatState;
        uint256 tokenId = tokenByAnchor(anchor);
        emit FloatingStateChange(anchor, tokenId, newFloatState, msg.sender);
        _emitLockStatus(tokenId);
    }

     /// @notice Indicates whether any of OWNER, ISSUER, (ASSET) is allowed to start floating
    function floatStartAuthorization() external view returns (Authorization canStartFloating) {
        return _getERC6956FloatableStorage().floatStartAuthorization;
    }
    
    /// @notice Indicates whether any of OWNER, ISSUER, (ASSET) is allowed to stop floating
    function floatStopAuthorization() external view returns (Authorization canStartFloating) {
        return _getERC6956FloatableStorage().floatStopAuthorization;
    }

    function floating(bytes32 anchor) public view returns (bool){
        ERC6956FloatableStorage storage $ = _getERC6956FloatableStorage();
        return _floating($.allFloating, $.floatingStateByAnchor[anchor]);
    }    

    
    function locked(uint256 tokenId) external view override returns (bool) {
        // If an anchor is floating, it can be transferred like 
        // ERC-721 NFTs. So according to ERC-5192, this can be considered
        // unlocked.
        return !floating(anchorByToken(tokenId));
    }


    // ########################################################## VALID ANCHORS

     /// @custom:storage-location erc7201:storage.ERC6956ValidAnchorsStorage
    struct ERC6956ValidAnchorsStorage {
        /// @dev The merkle-tree root node, where proof is validated against. Update via updateValidAnchors(). Use salt-leafs in merkle-trees!
        bytes32 _validAnchorsMerkleRoot;
    }

     // keccak256(abi.encode(uint256(keccak256("storage.ERC6956AttestedTransferLimitedStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC6956ValidAnchorsStorageLocation = 0x8b0b1cd3e4b42b2433d599b6d64abf9099daeccd117668a2a3c1533a96708800;

    function _getERC6956ValidAnchorsStorage() private pure returns (ERC6956ValidAnchorsStorage storage $) {
        assembly {
            $.slot := ERC6956ValidAnchorsStorageLocation
        }
    }


    //////// GENERAL

    function _beforeUpdate(address to, uint256 tokenId, address auth) internal virtual
        override 
    {
        bytes32 anchor = anchorByToken(tokenId);
                    
            if(!anchorIsReleased(anchor)) {
                // Only write when not already released - this saves gas, as memory-write is quite expensive compared to IF
                if(floating(anchor)) {
                    _setAnchorIsReleased(anchor, true);
                }
            }

            super._beforeUpdate(to, tokenId, auth);

    }

    function _beforeAttestationUse(bytes32 anchor, address to, bytes memory data) internal view virtual override {
        // empty, can be overwritten by derived conctracts.
        require(attestationUsagesLeft(anchor) > 0, "ERC6956-E24");

        // IERC6956ValidAnchors check anchor is indeed valid in contract
        require(data.length > 0, "ERC6956-E25");
        bytes32[] memory proof;
        (proof) = abi.decode(data, (bytes32[])); // Decode it with potentially more data following. If there is more data, this may be passed on to safeTransfer
        require(anchorValid(anchor, proof), "ERC6956-E26");

        super._beforeAttestationUse(anchor, to, data);
    }


    /// @notice Update the Merkle root containing the valid anchors. Consider salt-leaves!
    /// @dev Proof (transferAnchor) needs to be provided from this tree. 
    /// @dev The merkle-tree needs to contain at least one "salt leaf" in order to not publish the complete merkle-tree when all anchors should have been dropped at least once. 
    /// @param merkleRootNode The root, containing all anchors we want validated.
    function updateValidAnchors(bytes32 merkleRootNode) public onlyMaintainer() {
        _getERC6956ValidAnchorsStorage()._validAnchorsMerkleRoot = merkleRootNode;
        emit ValidAnchorsUpdate(merkleRootNode, msg.sender);
    }

    function anchorValid(bytes32 anchor, bytes32[] memory proof) public virtual view returns (bool) {
        return MerkleProof.verify(
            proof,
            _getERC6956ValidAnchorsStorage()._validAnchorsMerkleRoot,
            keccak256(bytes.concat(keccak256(abi.encode(anchor)))));
    }

   

    function __ERC6956Full_init(AttestationLimitPolicy _limitUpdatePolicy) internal {
        __ERC6956_init();
        
        _getERC6956AttestedTransferLimitedStorage().attestationLimitPolicy = _limitUpdatePolicy;
        // Note per default no-one change floatability. canStartFloating and canStopFloating needs to be configured first!               
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return
            interfaceId == type(IERC6956AttestationLimited).interfaceId ||
            interfaceId == type(IERC6956Floatable).interfaceId ||
            interfaceId == type(IERC6956ValidAnchors).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
