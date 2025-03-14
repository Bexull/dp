// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract URLComplaint {
    struct Complaint {
        string url;
        string userId;  // ID из MongoDB
        string email;   // Email пользователя
    }

    mapping(string => Complaint[]) public complaints; // Жалобы по URL

    event URLReported(string url, string userId, string email, uint256 count);

    function reportURL(string memory url, string memory userId, string memory email) public {
        // Проверяем, жаловался ли этот пользователь
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
}
