// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract URLComplaint is Initializable {
    struct Complaint {
        string url;
        string userId;
        string email;
    }

    mapping(string => Complaint[]) private complaints;
    address private admin;

    event URLReported(string url, string userId, string email, uint256 count);
    event PhishingSiteAdded(string url, uint256 timestamp, string siteHash, string prevSiteHash);

    function initialize() public initializer {
        admin = msg.sender;
    }

    function reportURL(string memory url, string memory userId, string memory email) public {
        for (uint i = 0; i < complaints[url].length; i++) {
            require(
                keccak256(abi.encodePacked(complaints[url][i].userId)) != keccak256(abi.encodePacked(userId)),
                "User has already reported this URL!"
            );
        }

        complaints[url].push(Complaint(url, userId, email));
        emit URLReported(url, userId, email, complaints[url].length);
    }

    function getComplaintCount(string memory url) public view returns (uint256) {
        return complaints[url].length;
    }

    // 🔹 Структура для хранения фишинговых сайтов
    struct PhishingSite {
        string url;
        uint256 timestamp;
        string siteHash;
        string prevSiteHash;
    }

    mapping(string => PhishingSite) private phishingSites;
    string private lastSiteHash;  // Хеш последнего фишингового сайта

    function addPhishingSite(string memory url, string memory siteHash) public {
        require(phishingSites[siteHash].timestamp == 0, "This site is already marked as phishing!");

        phishingSites[siteHash] = PhishingSite(url, block.timestamp, siteHash, lastSiteHash);
        lastSiteHash = siteHash;

        emit PhishingSiteAdded(url, block.timestamp, siteHash, lastSiteHash);
    }

    function getPhishingSite(string memory siteHash) public view returns (PhishingSite memory) {
        return phishingSites[siteHash];
    }

    // ✅ **НОВАЯ ФУНКЦИЯ: Получение последнего фишингового сайта**
    function getLastPhishingSite() public view returns (string memory, uint256, string memory, string memory) {
        require(bytes(lastSiteHash).length > 0, "No phishing sites recorded.");
        PhishingSite memory lastSite = phishingSites[lastSiteHash];
        return (lastSite.url, lastSite.timestamp, lastSite.siteHash, lastSite.prevSiteHash);
    }
}
