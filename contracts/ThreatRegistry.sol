// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SENTRIX Decentralized Threat Intelligence Registry
 * @notice Immutable cryptographic registry for verified cyber threat reports with dispute & revision governance.
 * @dev Stores cryptographic commitments (SHA-256) of forensic reports
 * without exposing PII, credentials, or sensitive payloads on-chain.
 */
contract ThreatRegistry {
    enum RecordStatus { ACTIVE, DISPUTED, REVISED, REVOKED }

    struct ThreatRecord {
        bytes32 reportHash;      // SHA-256 canonical hash commitment
        address reporter;        // Submitting authority / analyst address
        uint256 timestamp;       // Block timestamp of registration
        string category;         // Threat classification (e.g., PHISHING, MALWARE, SCAM)
        uint8 severityScore;     // Severity rating (0-100)
        string metadataUri;      // Canonical non-identifying reference URI (e.g., sentrix://report/...)
        RecordStatus status;     // Lifecycle status: ACTIVE, DISPUTED, REVISED, REVOKED
        bytes32 revisionHash;    // Hash commitment of revised evidence (0 if unrevised)
        uint256 disputeCount;    // Total number of formal disputes filed against this record
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
        uint8 severityScore,
        string metadataUri
    );

    event ThreatDisputed(
        bytes32 indexed reportHash,
        address indexed disputer,
        string disputeReasonUri,
        uint256 timestamp
    );

    event ThreatRevised(
        bytes32 indexed reportHash,
        address indexed reviser,
        uint8 newSeverityScore,
        bytes32 newRevisionHash,
        string newMetadataUri,
        uint256 timestamp
    );

    event ThreatStatusUpdated(
        bytes32 indexed reportHash,
        RecordStatus oldStatus,
        RecordStatus newStatus,
        uint256 timestamp
    );

    error RecordAlreadyExists(bytes32 reportHash);
    error RecordNotFound(bytes32 reportHash);
    error InvalidHash();
    error Unauthorized();
    error InvalidMetadataUri();
    error InvalidSeverity();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Validates that metadataUri adheres strictly to non-identifying format:
     * - Must not be empty, max 128 characters.
     * - Must not contain plain-text at-sign or external HTTP/HTTPS URLs (prevents cleartext target leaking).
     */
    function _validateNonIdentifyingMetadata(string calldata uri) internal pure {
        bytes memory b = bytes(uri);
        if (b.length == 0 || b.length > 128) revert InvalidMetadataUri();

        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == 0x40) revert InvalidMetadataUri(); // '@' character forbidden
            if (i + 7 <= b.length) {
                if (b[i] == "h" && b[i+1] == "t" && b[i+2] == "t" && b[i+3] == "p" && b[i+4] == ":" && b[i+5] == "/" && b[i+6] == "/") {
                    revert InvalidMetadataUri(); // http:// forbidden
                }
            }
            if (i + 8 <= b.length) {
                if (b[i] == "h" && b[i+1] == "t" && b[i+2] == "t" && b[i+3] == "p" && b[i+4] == "s" && b[i+5] == ":" && b[i+6] == "/" && b[i+7] == "/") {
                    revert InvalidMetadataUri(); // https:// forbidden
                }
            }
        }
    }

    function registerThreat(
        bytes32 reportHash,
        string calldata category,
        uint8 severityScore,
        string calldata metadataUri
    ) external returns (uint256 reportId) {
        if (reportHash == bytes32(0)) revert InvalidHash();
        if (recordsByHash[reportHash].timestamp != 0) revert RecordAlreadyExists(reportHash);
        if (severityScore > 100) revert InvalidSeverity();
        _validateNonIdentifyingMetadata(metadataUri);

        ThreatRecord memory rec = ThreatRecord({
            reportHash: reportHash,
            reporter: msg.sender,
            timestamp: block.timestamp,
            category: category,
            severityScore: severityScore,
            metadataUri: metadataUri,
            status: RecordStatus.ACTIVE,
            revisionHash: bytes32(0),
            disputeCount: 0
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
            severityScore,
            metadataUri
        );
    }

    /**
     * @notice Files a formal dispute against a registered threat commitment.
     */
    function disputeThreat(bytes32 reportHash, string calldata disputeReasonUri) external {
        if (recordsByHash[reportHash].timestamp == 0) revert RecordNotFound(reportHash);
        _validateNonIdentifyingMetadata(disputeReasonUri);

        ThreatRecord storage rec = recordsByHash[reportHash];
        rec.status = RecordStatus.DISPUTED;
        rec.disputeCount += 1;

        emit ThreatDisputed(reportHash, msg.sender, disputeReasonUri, block.timestamp);
    }

    /**
     * @notice Updates or revises a threat commitment with new evidence.
     */
    function reviseThreat(
        bytes32 reportHash,
        uint8 newSeverityScore,
        bytes32 newRevisionHash,
        string calldata newMetadataUri
    ) external {
        if (recordsByHash[reportHash].timestamp == 0) revert RecordNotFound(reportHash);
        if (newSeverityScore > 100) revert InvalidSeverity();
        ThreatRecord storage rec = recordsByHash[reportHash];
        if (msg.sender != rec.reporter && msg.sender != owner) revert Unauthorized();
        _validateNonIdentifyingMetadata(newMetadataUri);

        rec.severityScore = newSeverityScore;
        rec.revisionHash = newRevisionHash;
        rec.metadataUri = newMetadataUri;
        rec.status = RecordStatus.REVISED;

        emit ThreatRevised(reportHash, msg.sender, newSeverityScore, newRevisionHash, newMetadataUri, block.timestamp);
    }

    /**
     * @notice Resolves a pending dispute by owner/governance authority.
     */
    function resolveDispute(
        bytes32 reportHash,
        RecordStatus resolutionStatus,
        uint8 newSeverityScore
    ) external onlyOwner {
        if (recordsByHash[reportHash].timestamp == 0) revert RecordNotFound(reportHash);
        if (newSeverityScore > 100) revert InvalidSeverity();
        ThreatRecord storage rec = recordsByHash[reportHash];
        RecordStatus oldStatus = rec.status;
        rec.status = resolutionStatus;
        rec.severityScore = newSeverityScore;

        emit ThreatStatusUpdated(reportHash, oldStatus, resolutionStatus, block.timestamp);
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
            string memory metadataUri,
            RecordStatus status,
            bytes32 revisionHash,
            uint256 disputeCount
        )
    {
        ThreatRecord memory rec = recordsByHash[reportHash];
        if (rec.timestamp == 0) {
            return (false, address(0), 0, "", 0, "", RecordStatus.ACTIVE, bytes32(0), 0);
        }
        return (
            true,
            rec.reporter,
            rec.timestamp,
            rec.category,
            rec.severityScore,
            rec.metadataUri,
            rec.status,
            rec.revisionHash,
            rec.disputeCount
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
            string memory metadataUri,
            RecordStatus status,
            bytes32 revisionHash,
            uint256 disputeCount
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
            rec.metadataUri,
            rec.status,
            rec.revisionHash,
            rec.disputeCount
        );
    }
}
