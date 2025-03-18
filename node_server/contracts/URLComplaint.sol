// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract URLComplaint is Initializable {
    address private admin;

    // ✅ Сохраняем, жаловался ли пользователь на сайт
    mapping(string => mapping(string => bool)) private hasComplained;
    mapping(string => uint256) private complaintCounts;

    event URLReported(string url, string userId, uint256 count);
    event PhishingSiteAdded(string url, uint256 timestamp, string siteHash, string prevSiteHash);

    function initialize() public initializer {
        admin = msg.sender;
    }

    function reportURL(string memory url, string memory userId) public {
        require(!hasComplained[url][userId], "User has already reported this URL!");

        hasComplained[url][userId] = true;
        complaintCounts[url] += 1;

        emit URLReported(url, userId, complaintCounts[url]);
    }

    function getComplaintCount(string memory url) public view returns (uint256) {
        return complaintCounts[url];
    }

    struct PhishingSite {
        string url;
        uint256 timestamp;
        string siteHash;
        string prevSiteHash;
    }

    mapping(string => PhishingSite) private phishingSites;
    string private lastSiteHash;

    function addPhishingSite(string memory url, string memory siteHash) public {
        require(phishingSites[siteHash].timestamp == 0, "This site is already marked as phishing!");

        phishingSites[siteHash] = PhishingSite(url, block.timestamp, siteHash, lastSiteHash);
        lastSiteHash = siteHash;

        emit PhishingSiteAdded(url, block.timestamp, siteHash, lastSiteHash);
    }

    function getPhishingSite(string memory siteHash) public view returns (PhishingSite memory) {
        return phishingSites[siteHash];
    }

    function getLastPhishingSite() public view returns (string memory, uint256, string memory, string memory) {
        require(bytes(lastSiteHash).length > 0, "No phishing sites recorded.");
        PhishingSite memory lastSite = phishingSites[lastSiteHash];
        return (lastSite.url, lastSite.timestamp, lastSite.siteHash, lastSite.prevSiteHash);
    }
}
