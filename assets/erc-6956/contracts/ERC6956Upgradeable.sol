// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./erc6956/ERC6956Base.sol";

contract ERC6956Upgradeable is
    Initializable, 
    UUPSUpgradeable,
    ERC721Upgradeable,
    ERC721BurnableUpgradeable,
    ERC6956Base
{
    function initialize(string memory name, string memory symbol) public initializer {
        __ERC721_init(name, symbol);
        __ERC6956_init();
    }

    function _update( address to, uint256 tokenId, address auth)
        internal virtual
        override(ERC721Upgradeable, ERC6956Base)
        returns (address) {
            _beforeUpdate(to, tokenId, auth); // Calls ERC6956 hook
            return ERC721Upgradeable._update(to, tokenId, auth);
        }

    function approve(address to, uint256 tokenId) public virtual override {
        _checkERC6956Approval(to, tokenId);
        ERC721Upgradeable.approve(to, tokenId);
    }

    function _ownerOf(uint256 tokenId) internal view virtual override(ERC6956Base, ERC721Upgradeable) returns (address)  {
        return ERC721Upgradeable._ownerOf(tokenId);
    }

    function _erc721Approve(address to, uint256 tokenId, address auth) internal virtual override(ERC6956Base) {
        // Proxy to ERC721
        ERC721Upgradeable._approve(to, tokenId, auth);
    }

    function _isAuthorized(address owner, address spender, uint256 tokenId) internal view virtual override(ERC6956Base, ERC721Upgradeable) returns (bool) {
        return ERC721Upgradeable._isAuthorized(owner, spender, tokenId);
    }

    function _baseURI() internal view virtual override(ERC6956Base, ERC721Upgradeable) returns (string memory) {
        return ERC6956Base._baseURI();
    }

    function tokenURI(uint256 tokenId) public view override(ERC6956Base, ERC721Upgradeable) returns (string memory) {
        return ERC6956Base.tokenURI(tokenId);
    }
/**
     * @dev UUPSUpgradeable authorizes maintainers to upgrade the contract
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyMaintainer() {}
    
     function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC6956Base, ERC721Upgradeable)
        returns (bool) {
            return ERC6956Base.supportsInterface(interfaceId) || ERC721Upgradeable.supportsInterface(interfaceId);
        }
}