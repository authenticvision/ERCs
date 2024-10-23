// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

import "@openzeppelin/contracts/utils/Strings.sol";
import "./IERC6956.sol";

/** Used for several authorization mechanisms, e.g. who can burn, who can set approval, ... 
 * @dev Specifying the role in the ecosystem. Used in conjunction with IERC6956.Authorization
 */
enum Role {
    OWNER,  // =0, The owner of the digital token
    ISSUER, // =1, The issuer (contract) of the tokens, typically represented through a MAINTAINER_ROLE, the contract owner etc.
    ASSET,  // =2, The asset identified by the anchor
    INVALID // =3, Reserved, do not use.
}

/**
 * @title ASSET-BOUND NFT minimal reference implementation 
 * @author Thomas Bergmueller (@tbergmueller)
 * 
 * @dev Error messages
 * ```
 * ERROR | Message
 * ------|-------------------------------------------------------------------
 * E1    | Only maintainer allowed
 * E2    | No permission to burn
 * E3    | Token does not exist, call transferAnchor first to mint
 * E4    | batchSize must be 1
 * E5    | Token not transferable
 * E6    | Token already owned
 * E7    | Not authorized based on ERC6956Authorization
 * E8    | Attestation not signed by trusted oracle
 * E9    | Attestation already used
 * E10   | Attestation not valid yet
 * E11   | Attestation expired 
 * E12   | Attestation expired (contract limit)
 * E13   | Invalid signature length
 * E14-20| Reserved for future use
 * ```
 */
abstract contract ERC6956Base is
    IERC6956 
{
    /// @custom:storage-location erc7201:storage.ERC6956
    struct ERC6956Storage {
        mapping(bytes32 => bool)  _anchorIsReleased; // currently released anchors. Per default, all anchors are dropped, i.e. 1:1 bound
        mapping(address => bool)  maintainers;
        /// @notice Resolves tokenID to anchor. Inverse of tokenByAnchor
        mapping(uint256 => bytes32)  anchorByToken;
        /// @notice Resolves Anchor to tokenID. Inverse of anchorByToken
        mapping(bytes32 => uint256)  tokenByAnchor;
        mapping(address => bool)  _trustedOracles;
        /// @dev stores the anchors for each attestation
        mapping(bytes32 => bytes32) _anchorByUsedAttestation;
        /// @dev stores handed-back tokens (via burn)
        mapping (bytes32 => uint256) _burnedTokensByAnchor;
        /**
        * @dev Counter to keep track of issued tokens
        */
        uint256 _tokenIdCounter;
        /// @dev Default validity timespan of attestation. In validateAttestation the attestationTime is checked for MIN(defaultAttestationvalidity, attestation.expiry)
        uint256 maxAttestationExpireTime;
        Authorization burnAuthorization;
        Authorization approveAuthorization;
        /// @dev Records the number of transfers done for each attestation
        mapping(bytes32 => uint256) attestationsUsedByAnchor;
        /**
      * @dev Base URI, MUST end with a slash. Will be used as `{baseURI}{tokenId}` in tokenURI() function
      */
      string _baseUri; // needs to end with '/'
    }

    // keccak256(abi.encode(uint256(keccak256("storage.ERC6956")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC6956StorageLocation = 0x54ff554d2ec0da0e195180df78f4c5389b8f9d39ea45df4f9658bdc428047200; 

    function _getERC6956Storage() private pure returns (ERC6956Storage storage $) {
        assembly {
            $.slot := ERC6956StorageLocation
        }
    }
    modifier onlyMaintainer() {
        require(isMaintainer(msg.sender), "ERC6956-E1");
        _;
    }

    function _setAnchorIsReleased(bytes32 anchor, bool isReleased) internal {
        _getERC6956Storage()._anchorIsReleased[anchor] = isReleased;
    }

  function __ERC6956_init() internal {
    ERC6956Storage storage $ = _getERC6956Storage();
        $.maintainers[msg.sender] = true; // deployer is automatically maintainer

        // OWNER and ASSET shall normally be in sync anyway, so this is reasonable default 
        // authorization for approve and burn, as it mimics ERC-721 behavior
        $.burnAuthorization = Authorization.OWNER_AND_ASSET;
        $.approveAuthorization = Authorization.OWNER_AND_ASSET;

        $._tokenIdCounter = 0;
        $.maxAttestationExpireTime = 5*60; // 5min valid per default

  }

    /**
     * @notice Behaves like ERC721 burn() for wallet-cleaning purposes. Note only the tokenId (as a wrapper) is burned, not the ASSET represented by the ANCHOR.
     * @dev 
     * - tokenId is remembered for the anchor, to ensure a later transferAnchor(), which would mint, assigns the same tokenId. This ensures strict 1:1 relation
     * - For burning, the anchor needs to be released. This forced release FOR BURNING ONLY is allowed for owner() or approvedOwner().
     * 
     * @param tokenId The token that shall be burned
     */
    function _beforeBurn(uint256 tokenId, address auth) internal view
    {
        ERC6956Storage storage $ = _getERC6956Storage();
        // remember the tokenId of burned tokens, s.t. one can issue the token with the same number again

        bytes32 anchor = $.anchorByToken[tokenId];
        require(_roleBasedAuthorization(anchor, createAuthorizationMap($.burnAuthorization), auth), "ERC6956-E2");   
    }

    function burnAnchor(bytes memory attestation, bytes memory data) public virtual
        authorized(Role.ASSET, createAuthorizationMap(_getERC6956Storage().burnAuthorization))
     {
        address to;
        bytes32 anchor;
        bytes32 attestationHash;
        (to, anchor, attestationHash) = decodeAttestationIfValid(attestation, data);
        _commitAttestation(to, anchor, attestationHash);
        uint256 tokenId = _getERC6956Storage().tokenByAnchor[anchor];
        // Attestation means current owner implicitely authorizes the action.
        _update(address(0), tokenId, _ownerOf(tokenId)); 
    }

    function burnAnchor(bytes memory attestation) public virtual {
        return burnAnchor(attestation, "");
    }

    function approveAnchor(bytes memory attestation, bytes memory data) public virtual 
        authorized(Role.ASSET, createAuthorizationMap(_getERC6956Storage().approveAuthorization))
    {
        address to;
        bytes32 anchor;
        bytes32 attestationHash;
        (to, anchor, attestationHash) = decodeAttestationIfValid(attestation, data);
        _commitAttestation(to, anchor, attestationHash);
        uint256 tokenId = _getERC6956Storage().tokenByAnchor[anchor];
        require(tokenId>0, "ERC6956-E3");
        // Attestation means that the current holder agrees/authorizes temporarily
        _erc721Approve(to, tokenId, _ownerOf(tokenId));
    }

    // approveAuth == ISSUER does not really make sense.. so no separate implementation, since ERC-721.approve already implies owner...

  
    function _checkERC6956Approval(address to, uint256 tokenId) internal virtual
      authorized(Role.OWNER, createAuthorizationMap(_getERC6956Storage().approveAuthorization))
    {}

    function approveAnchor(bytes memory attestation) public virtual {
        return approveAnchor(attestation, "");
    }
    
    /**
     * @notice Adds or removes a trusted oracle, used when verifying signatures in `decodeAttestationIfValid()`
     * @dev Emits OracleUpdate
     * @param oracle address of oracle
     * @param doTrust true to add, false to remove
     */
    function updateOracle(address oracle, bool doTrust) public
        onlyMaintainer() 
    {
        _getERC6956Storage()._trustedOracles[oracle] = doTrust;
        emit OracleUpdate(oracle, doTrust);
    }

    /**
     * @dev A very simple function which MUST return false, when `a` is not a maintainer
     *      When derived contracts extend ERC6956 contract, this function may be overridden
     *      e.g. by using AccessControl, onlyOwner or other common mechanisms
     * 
     *      Having this simple mechanism in the reference implementation ensures that the reference
     *      implementation is fully ERC-6956 compatible 
     */
    function isMaintainer(address a) public virtual view returns (bool) {
        return _getERC6956Storage().maintainers[a];
    } 
      

    function createAuthorizationMap(Authorization _auth) public pure returns (uint256)  {
       uint256 authMap = 0;
       if(_auth == Authorization.OWNER 
            || _auth == Authorization.OWNER_AND_ASSET 
            || _auth == Authorization.OWNER_AND_ISSUER 
            || _auth == Authorization.ALL) {
        authMap |= uint256(1<<uint256(Role.OWNER));
       } 
       
       if(_auth == Authorization.ISSUER 
            || _auth == Authorization.ASSET_AND_ISSUER 
            || _auth == Authorization.OWNER_AND_ISSUER 
            || _auth == Authorization.ALL) {
        authMap |= uint256(1<<uint256(Role.ISSUER));
       }

       if(_auth == Authorization.ASSET 
            || _auth == Authorization.ASSET_AND_ISSUER 
            || _auth == Authorization.OWNER_AND_ASSET 
            || _auth == Authorization.ALL) {
        authMap |= uint256(1<<uint256(Role.ASSET));
       }

       return authMap;
    }

    function _roleBasedAuthorization(bytes32 anchor, uint256 authorizationMap, address auth) internal view returns (bool) {
      uint256 tokenId = _getERC6956Storage().tokenByAnchor[anchor];        
        Role myRole = Role.INVALID;
        Role alternateRole = Role.INVALID;
        
        if(_isAuthorized(_ownerOf(tokenId), auth, tokenId)) {
            myRole = Role.OWNER;
        }

        if(isMaintainer(auth)) {
            alternateRole = Role.ISSUER;
        }

        return hasAuthorization(myRole, authorizationMap) 
                    || hasAuthorization(alternateRole, authorizationMap);
    }

    function _roleBasedAuthorization(bytes32 anchor, uint256 authorizationMap) internal view returns (bool) {
      return _roleBasedAuthorization(anchor, authorizationMap, msg.sender);
    }
   
    ///@dev Hook executed before decodeAttestationIfValid returns. Override in derived contracts
    function _beforeAttestationUse(bytes32 anchor, address to, bytes memory data) internal view virtual {}
    

    function _beforeUpdate( address to, uint256 tokenId, address auth)
        internal virtual
    {
        ERC6956Storage storage $ = _getERC6956Storage();
        bytes32 anchor = $.anchorByToken[tokenId];

        // Use the non-tokenIdExists-required version of owner-of, also allow minting in
        // the same code-path.
        emit AnchorTransfer(_ownerOf(tokenId), to, anchor, tokenId);
        if(to == address(0)) {
            // we are burning, ensure the mapping is deleted BEFORE the transfer
            // to avoid reentrant-attacks
            _beforeBurn(tokenId, auth);

            // For the issuer to burn, we need to approve the issuer
            // Note that potential issuer-burning has already been checked in _beforeBurn
            if(isMaintainer(msg.sender)) {
              _erc721Approve(msg.sender, tokenId, _ownerOf(tokenId));
            }

            $._burnedTokensByAnchor[anchor] = tokenId; // Remember tokenId for a potential re-mint
            delete $.tokenByAnchor[anchor];
            delete $.anchorByToken[tokenId]; 
        }        
        else {
            require($._anchorIsReleased[anchor], "ERC6956-E5");
        }

        delete $._anchorIsReleased[anchor]; // make sure anchor is non-released after the transfer again
   }

    /// @dev hook called after an anchor is minted
    function _afterAnchorMint(address to, bytes32 anchor, uint256 tokenId) internal virtual {}

    /**
     * @notice Add (_add=true) or remove (_add=false) a maintainer
     * @dev Note this is a trivial implementation, which can leave the contract without a maintainer.
     * Since the function is access-controlled via onlyMaintainer, this results in the contract
     * becoming unmaintainable. 
     * This may be desired behavior, for example if the contract shall become immutable until 
     * all eternity, therefore making a project truly trustless. 
     */
    function updateMaintainer(address _maintainer, bool _add) public onlyMaintainer() {  
        _getERC6956Storage().maintainers[_maintainer] = _add;
    }

    /// @dev Verifies a anchor is valid and mints a token to the target address.
    /// Internal function to be called whenever minting is needed.
    /// Parameters:
    /// @param to Beneficiary account address
    /// @param anchor The anchor (from Merkle tree)
    function _anchorMint(address to, bytes32 anchor) internal virtual {
        ERC6956Storage storage $ = _getERC6956Storage();

        assert($.tokenByAnchor[anchor] <= 0); // safety for contract-internal errors
        uint256 tokenId = $._burnedTokensByAnchor[anchor];

        if(tokenId < 1) {
            $._tokenIdCounter = $._tokenIdCounter + 1;
            tokenId = $._tokenIdCounter;
        }

        assert($.anchorByToken[tokenId] <= 0); // safety for contract-internal errors
        $.anchorByToken[tokenId] = anchor;
        $.tokenByAnchor[anchor] = tokenId;
        _update(to, tokenId, address(0));
        _afterAnchorMint(to, anchor, tokenId);
    }

    function _commitAttestation(address to, bytes32 anchor, bytes32 attestationHash) internal {
        ERC6956Storage storage $ = _getERC6956Storage();
        $._anchorByUsedAttestation[attestationHash] = anchor;
        uint256 totalAttestationsByAnchor = $.attestationsUsedByAnchor[anchor] +1;
        $.attestationsUsedByAnchor[anchor] = totalAttestationsByAnchor;
        emit AttestationUse(to, anchor, attestationHash, totalAttestationsByAnchor );
    }

    function transferAnchor(bytes memory attestation, bytes memory data) public virtual
    {
        ERC6956Storage storage $ = _getERC6956Storage();
    
        bytes32 anchor;
        address to;
        bytes32 attestationHash;
        (to, anchor, attestationHash) = decodeAttestationIfValid(attestation, data);
        _commitAttestation(to, anchor, attestationHash); // commit already here, will be reverted in error case anyway

        uint256 tokenId = $.tokenByAnchor[anchor]; // tokenID, null if not exists
        address from = address(0); // owneraddress or 0x00, if not exists
        
        $._anchorIsReleased[anchor] = true; // Attestation always temporarily releases the anchor       

        if(tokenId > 0) {
            from = _ownerOf(tokenId);
            require(from != to, "ERC6956-E6");
            _update(to, tokenId, from);
        } else {
            _anchorMint(to, anchor);
        }
    }

    function transferAnchor(bytes memory attestation) public virtual {
        return transferAnchor(attestation, "");
    }

    function anchorIsReleased(bytes32 anchor) public view returns (bool isReleased) {
        return _getERC6956Storage()._anchorIsReleased[anchor];
    }

    function _setAnchorRelease(bytes32 anchor, bool isReleased) internal {
        _getERC6956Storage()._anchorIsReleased[anchor] = isReleased;
    }
    

    function hasAuthorization(Role _role, uint256 _auth ) public pure returns (bool) {
        uint256 result = uint256(_auth & (1 << uint256(_role)));
        return result > 0;
    }

    modifier authorized(Role _role, uint256 _authMap) {
        require(hasAuthorization(_role, _authMap), "ERC6956-E7");
        _;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        returns (bool)
    {
        return
            interfaceId == type(IERC6956).interfaceId;
    }

    /**
     * @notice Returns whether a certain address is registered as trusted oracle, i.e. attestations signed by this address are accepted in `decodeAttestationIfValid`
     * @dev This function may be overwritten when extending ERC-6956, e.g. when other oracle-registration mechanics are used
     * @param oracleAddress Address of the oracle in question
     * @return isTrusted True, if oracle is trusted
     */
    function isTrustedOracle(address oracleAddress) public virtual view returns (bool isTrusted) {
        return _getERC6956Storage()._trustedOracles[oracleAddress];
    }
    
    function tokenByAnchor(bytes32 anchor) public view returns(uint256 tokenId) {
        return _getERC6956Storage().tokenByAnchor[anchor];
    }

    function anchorByToken(uint256 tokenId) public view returns (bytes32 anchor) {
        return _getERC6956Storage().anchorByToken[tokenId];
    }

    function approveAuthorization() public view returns (Authorization approveAuth) {
        return _getERC6956Storage().approveAuthorization;
    }

    function burnAuthorization() public view returns (Authorization burnAuth) {
        return _getERC6956Storage().burnAuthorization;
    }

    function attestationsUsedByAnchor(bytes32 anchor) public view returns (uint256 usages) {
        return _getERC6956Storage().attestationsUsedByAnchor[anchor];
    }

    function decodeAttestationIfValid(bytes memory attestation, bytes memory data) public view returns (address to, bytes32 anchor, bytes32 attestationHash) {

        ERC6956Storage storage $ = _getERC6956Storage();

        uint256 attestationTime;
        uint256 validStartTime;
        uint256 validEndTime;
        bytes memory signature;
        bytes32[] memory proof;

        attestationHash = keccak256(attestation);
        (to, anchor, attestationTime, validStartTime, validEndTime, signature) = abi.decode(attestation, (address, bytes32, uint256, uint256, uint256, bytes));
                
        bytes32 messageHash = keccak256(abi.encodePacked(to, anchor, attestationTime, validStartTime, validEndTime, proof));
        address signer = _extractSigner(messageHash, signature);

        // Check if from trusted oracle
        require(isTrustedOracle(signer), "ERC6956-E8");
        require($._anchorByUsedAttestation[attestationHash] <= 0, "ERC6956-E9");

        // Check expiry
        uint256 timestamp = block.timestamp;
        
        require(timestamp > validStartTime, "ERC6956-E10");
        require(attestationTime + $.maxAttestationExpireTime > block.timestamp, "ERC6956-E11");
        require(validEndTime > block.timestamp, "ERC6956-E112");

        
        // Calling hook!
        _beforeAttestationUse(anchor, to, data);
        return(to,  anchor, attestationHash);
    }

    /// @notice Compatible with ERC721.tokenURI(). Returns {baseURI}{anchor}
    /// @dev Returns when called for tokenId=5, baseURI=https://myurl.com/collection/ and anchorByToken[5] =  0x12345
    /// Example:  https://myurl.com/collection/0x12345
    /// Works for non-burned tokens / active-Anchors only.
    /// Anchor-based tokenURIs are needed as an anchor's corresponding tokenId is only known after mint. 
    /// @param tokenId TokenID
    /// @return tokenURI Returns the Uniform Resource Identifier (URI) for `tokenId` token.
    function tokenURI(uint256 tokenId) public virtual view returns (string memory) {
      ERC6956Storage storage $ = _getERC6956Storage();        
        bytes32 anchor = $.anchorByToken[tokenId];
        string memory anchorString = Strings.toHexString(uint256(anchor));
        return bytes(_baseURI()).length > 0 ? string(abi.encodePacked(_baseURI(), anchorString)) : "";
    }

    function _baseURI() internal view virtual returns (string memory) {
        return _getERC6956Storage()._baseUri;
    }

    /// @notice Set a new BaseURI. Can be used with dynamic NFTs that have server APIs, IPFS-buckets
    /// or any other suitable system. Refer tokenURI(tokenId) for anchor-based or tokenId-based format.
    /// @param tokenBaseURI The token base-URI. Must end with slash '/'.
    function updateBaseURI(string calldata tokenBaseURI) public onlyMaintainer() {
        _getERC6956Storage()._baseUri = tokenBaseURI;
    }
    event BurnAuthorizationChange(Authorization burnAuth, address indexed maintainer);

    function updateBurnAuthorization(Authorization burnAuth) public onlyMaintainer() {
        _getERC6956Storage().burnAuthorization = burnAuth;
        emit BurnAuthorizationChange(burnAuth, msg.sender);
    }
    
    event ApproveAuthorizationChange(Authorization approveAuth, address indexed maintainer);

    function updateApproveAuthorization(Authorization approveAuth) public onlyMaintainer() {
        _getERC6956Storage().approveAuthorization = approveAuth;
        emit ApproveAuthorizationChange(approveAuth, msg.sender);
    }

  
    /*
     ########################## SIGNATURE MAGIC, 
     ########################## adapted from https://solidity-by-example.org/signature/
    */
   /**
    * Returns the signer of a message.
    *  
    *   OFF-CHAIN: 
    *   const [alice] = ethers.getSigners(); // = 0x3c44...
    *   const messageHash = ethers.utils.solidityKeccak256(["address", "bytes32"], [a, b]);
        const sig = await alice.signMessage(ethers.utils.arrayify(messageHash));

        ONCHAIN In this contract, call from 
        ```
        function (address a, bytes32 b, bytes memory sig) {
            messageHash = keccak256(abi.encodePacked(to, b));
            signer = extractSigner(messageHash, sig); // signer will be 0x3c44...
        }
        ```    * 
    * @param messageHash A keccak25(abi.encodePacked(...)) hash
    * @param sig Signature (length 65 bytes)
    * 
    * @return The signer
    */
   function _extractSigner(bytes32 messageHash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ERC6956-E13");
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract the r, s, and v parameters from the signature
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Ensure the v parameter is either 27 or 28
        // TODO is this needed?
        if (v < 27) {
            v += 27;
        }

        // Recover the public key from the signature and message hash
        // and convert it to an address
        address signer = ecrecover(ethSignedMessageHash, v, r, s);       
        return signer;
    }

    // PROXY-FUNCTIONS, which are implemented by ERC721 or ERC721Upgradeable
    function _update( address to, uint256 tokenId, address auth) internal virtual returns (address);
    function _ownerOf(uint256 tokenId) internal view virtual returns (address);
    // _approve is not marked virtual in ERC721, so we need a different function name
    function _erc721Approve(address to, uint256 tokenId, address auth) internal virtual;
    function _isAuthorized(address owner, address spender, uint256 tokenId) internal view virtual returns (bool);
}
