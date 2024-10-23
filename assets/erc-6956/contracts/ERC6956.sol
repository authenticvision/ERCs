// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./erc6956/ERC6956Base.sol";

contract ERC6956 is
    ERC721,
    ERC721Burnable,
    ERC6956Base 
{
    constructor(string memory _name, string memory _symbol)
        ERC721(_name, _symbol) {            
            __ERC6956_init();
    }

    function _update( address to, uint256 tokenId, address auth)
        internal virtual
        override(ERC721, ERC6956Base)
        returns (address) {
            _beforeUpdate(to, tokenId, auth); // Calls ERC6956 hook
            return ERC721._update(to, tokenId, auth);

        }

    function approve(address to, uint256 tokenId) public virtual override {
        _checkERC6956Approval(to, tokenId);
        ERC721.approve(to, tokenId);
    }

    function _ownerOf(uint256 tokenId) internal view virtual override(ERC6956Base, ERC721) returns (address)  {
        return ERC721._ownerOf(tokenId);
    }

    function _erc721Approve(address to, uint256 tokenId, address auth) internal virtual override(ERC6956Base) {
        // Proxy to ERC721
        ERC721._approve(to, tokenId, auth);
    }

    function _isAuthorized(address owner, address spender, uint256 tokenId) internal view virtual override(ERC6956Base, ERC721) returns (bool) {
        return ERC721._isAuthorized(owner, spender, tokenId);
    }

    function _baseURI() internal view virtual override(ERC6956Base, ERC721) returns (string memory) {
        return ERC6956Base._baseURI();
    }

    function tokenURI(uint256 tokenId) public view override(ERC6956Base, ERC721) returns (string memory) {
        return ERC6956Base.tokenURI(tokenId);
    }


     function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC6956Base, ERC721)
        returns (bool) {
            return ERC6956Base.supportsInterface(interfaceId) || ERC721.supportsInterface(interfaceId);
        }
}
