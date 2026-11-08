// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SENTRIX Decentralized Threat Intelligence Registry
 * @notice Immutable cryptographic registry for verified cyber threat reports.
 * @dev Stores cryptographic commitments (SHA-256) of forensic reports
 * without exposing PII, credentials, or sensitive payloads on-chain.
 */
contract ThreatRegistry {
    struct ThreatRecord {
        bytes32 reportHash;      // SHA-256 canonical hash commitment
        address reporter;        // Submitting authority / analyst address
        uint256 timestamp;       // Block timestamp of registration
        string category;         // Threat classification (e.g., PHISHING, MALWARE, SCAM)
        uint8 severityScore;     // Severity rating (0-100)
        string metadataUri;      // Canonical reference identifier or URI
    }

    // Mapping from reportHash to ThreatRecord
    mapping(bytes32 => ThreatRecord) public recordsByHash;
    // Sequential registry index
    ThreatRecord[] public registry;
    // Owner for governance operations
    address public owner;

    event ThreatRegistered(
        uint256 indexed reportId,
        bytes32 indexed reportHash,
        address indexed reporter,
        uint256 timestamp,
        string category,
        uint8 severityScore
    );

    event ThreatUpdated(
        uint256 indexed reportId,
        bytes32 indexed reportHash,
        uint8 newSeverityScore,
        uint256 updateTimestamp
    );

    error RecordAlreadyExists(bytes32 reportHash);
    error RecordNotFound(bytes32 reportHash);
    error InvalidHash();
    error Unauthorized();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerThreat(
        bytes32 reportHash,
        string calldata category,
        uint8 severityScore,
        string calldata metadataUri
    ) external returns (uint256 reportId) {
        if (reportHash == bytes32(0)) revert InvalidHash();
        if (recordsByHash[reportHash].timestamp != 0) revert RecordAlreadyExists(reportHash);

        ThreatRecord memory rec = ThreatRecord({
            reportHash: reportHash,
            reporter: msg.sender,
            timestamp: block.timestamp,
            category: category,
            severityScore: severityScore,
            metadataUri: metadataUri
        });

        recordsByHash[reportHash] = rec;
        registry.push(rec);
        reportId = registry.length - 1;

        emit ThreatRegistered(
            reportId,
            reportHash,
            msg.sender,
            block.timestamp,
            category,
            severityScore
        );
    }

    function verifyThreat(bytes32 reportHash)
        external
        view
        returns (
            bool exists,
            address reporter,
            uint256 timestamp,
            string memory category,
            uint8 severityScore,
            string memory metadataUri
        )
    {
        ThreatRecord memory rec = recordsByHash[reportHash];
        if (rec.timestamp == 0) {
            return (false, address(0), 0, "", 0, "");
        }
        return (
            true,
            rec.reporter,
            rec.timestamp,
            rec.category,
            rec.severityScore,
            rec.metadataUri
        );
    }

    function getRecordCount() external view returns (uint256) {
        return registry.length;
    }

    function getReport(uint256 index)
        external
        view
        returns (
            bytes32 reportHash,
            address reporter,
            uint256 timestamp,
            string memory category,
            uint8 severityScore,
            string memory metadataUri
        )
    {
        if (index >= registry.length) revert RecordNotFound(bytes32(0));
        ThreatRecord memory rec = registry[index];
        return (
            rec.reportHash,
            rec.reporter,
            rec.timestamp,
            rec.category,
            rec.severityScore,
            rec.metadataUri
        );
    }
}
