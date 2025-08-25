// IssuanceContract.test.ts
import { describe, expect, it, vi, beforeEach } from "vitest";

// Interfaces for type safety
interface ClarityResponse<T> {
  ok: boolean;
  value: T | number; // number for error codes
}

interface Issuer {
  name: string;
  registeredAt: number;
  active: boolean;
  verificationKey: string; // buff as string
}

interface Credential {
  did: string;
  issuer: string;
  vaccineType: string;
  batchNumber: string;
  issueDate: number;
  expiryDate: number | null;
  metadata: string;
  signature: string; // buff as string
  active: boolean;
}

interface IssuanceRecord {
  credentialId: string; // buff as string
  timestamp: number;
}

interface ContractState {
  paused: boolean;
  admin: string;
  issuers: Map<string, Issuer>;
  credentials: Map<string, Credential>;
  issuanceRecords: Map<string, IssuanceRecord>; // `${did}-${issueId}`
}

// Mock contract implementation
class IssuanceContractMock {
  private state: ContractState = {
    paused: false,
    admin: "deployer",
    issuers: new Map(),
    credentials: new Map(),
    issuanceRecords: new Map(),
  };

  private ERR_UNAUTHORIZED = 200;
  private ERR_NOT_FOUND = 201;
  private ERR_INVALID_ISSUER = 202;
  private ERR_PAUSED = 203;
  private ERR_INVALID_PARAM = 204;
  private ERR_ALREADY_ISSUED = 205;
  private ERR_INVALID_DID = 206;
  private ERR_METADATA_TOO_LONG = 207;
  private MAX_METADATA_LEN = 500;
  private MAX_BATCH_NUMBER_LEN = 50;
  private DID_PREFIX = "did:stack:";

  private generateCredentialId(did: string, vaccineType: string, batchNumber: string, issueDate: number): string {
    return `hash-${did}-${vaccineType}-${batchNumber}-${issueDate}`;
  }

  private validateDid(did: string): boolean {
    return did.startsWith(this.DID_PREFIX);
  }

  pauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = true;
    return { ok: true, value: true };
  }

  unpauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = false;
    return { ok: true, value: true };
  }

  setAdmin(caller: string, newAdmin: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.admin = newAdmin;
    return { ok: true, value: true };
  }

  registerIssuer(caller: string, name: string, verificationKey: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    if (this.state.issuers.has(caller)) {
      return { ok: false, value: this.ERR_ALREADY_ISSUED };
    }
    if (name.length === 0 || verificationKey.length === 0) {
      return { ok: false, value: this.ERR_INVALID_PARAM };
    }
    this.state.issuers.set(caller, {
      name,
      registeredAt: Date.now(),
      active: true,
      verificationKey,
    });
    return { ok: true, value: true };
  }

  deactivateIssuer(caller: string, issuer: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const issuerData = this.state.issuers.get(issuer);
    if (!issuerData) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    this.state.issuers.set(issuer, { ...issuerData, active: false });
    return { ok: true, value: true };
  }

  issueCredential(
    caller: string,
    did: string,
    vaccineType: string,
    batchNumber: string,
    issueDate: number,
    expiryDate: number | null,
    metadata: string,
    signature: string,
    issueId: number
  ): ClarityResponse<string> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const issuerData = this.state.issuers.get(caller);
    if (!issuerData || !issuerData.active) {
      return { ok: false, value: this.ERR_INVALID_ISSUER };
    }
    if (!this.validateDid(did)) {
      return { ok: false, value: this.ERR_INVALID_DID };
    }
    const credentialId = this.generateCredentialId(did, vaccineType, batchNumber, issueDate);
    if (this.state.credentials.has(credentialId)) {
      return { ok: false, value: this.ERR_ALREADY_ISSUED };
    }
    if (vaccineType.length === 0 || batchNumber.length > this.MAX_BATCH_NUMBER_LEN || metadata.length > this.MAX_METADATA_LEN || signature.length === 0) {
      return { ok: false, value: this.ERR_INVALID_PARAM };
    }
    this.state.credentials.set(credentialId, {
      did,
      issuer: caller,
      vaccineType,
      batchNumber,
      issueDate,
      expiryDate,
      metadata,
      signature,
      active: true,
    });
    this.state.issuanceRecords.set(`${did}-${issueId}`, {
      credentialId,
      timestamp: Date.now(),
    });
    return { ok: true, value: credentialId };
  }

  revokeCredential(caller: string, credentialId: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const credential = this.state.credentials.get(credentialId);
    if (!credential) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    const issuerData = this.state.issuers.get(caller);
    if (!issuerData || !issuerData.active || credential.issuer !== caller) {
      return { ok: false, value: this.ERR_INVALID_ISSUER };
    }
    this.state.credentials.set(credentialId, { ...credential, active: false });
    return { ok: true, value: true };
  }

  updateCredentialMetadata(caller: string, credentialId: string, newMetadata: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const credential = this.state.credentials.get(credentialId);
    if (!credential) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    const issuerData = this.state.issuers.get(caller);
    if (!issuerData || !issuerData.active || credential.issuer !== caller) {
      return { ok: false, value: this.ERR_INVALID_ISSUER };
    }
    if (newMetadata.length > this.MAX_METADATA_LEN) {
      return { ok: false, value: this.ERR_METADATA_TOO_LONG };
    }
    this.state.credentials.set(credentialId, { ...credential, metadata: newMetadata });
    return { ok: true, value: true };
  }

  getIssuer(issuer: string): ClarityResponse<Issuer | null> {
    return { ok: true, value: this.state.issuers.get(issuer) ?? null };
  }

  getCredential(credentialId: string): ClarityResponse<Credential | null> {
    return { ok: true, value: this.state.credentials.get(credentialId) ?? null };
  }

  getIssuanceRecord(did: string, issueId: number): ClarityResponse<IssuanceRecord | null> {
    return { ok: true, value: this.state.issuanceRecords.get(`${did}-${issueId}`) ?? null };
  }

  isIssuerActive(issuer: string): ClarityResponse<boolean> {
    const issuerData = this.state.issuers.get(issuer);
    return { ok: true, value: issuerData ? issuerData.active : false };
  }

  isCredentialActive(credentialId: string): ClarityResponse<boolean> {
    const credential = this.state.credentials.get(credentialId);
    return { ok: true, value: credential ? credential.active : false };
  }

  verifyIssuerSignature(credentialId: string, signature: string): ClarityResponse<boolean> {
    const credential = this.state.credentials.get(credentialId);
    if (!credential) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    const issuerData = this.state.issuers.get(credential.issuer);
    if (!issuerData) {
      return { ok: false, value: this.ERR_INVALID_ISSUER };
    }
    return { ok: true, value: credential.signature === signature };
  }

  isContractPaused(): ClarityResponse<boolean> {
    return { ok: true, value: this.state.paused };
  }

  getAdmin(): ClarityResponse<string> {
    return { ok: true, value: this.state.admin };
  }
}

// Test setup
const accounts = {
  deployer: "deployer",
  issuer: "wallet_1",
  user: "wallet_2",
};

describe("IssuanceContract", () => {
  let contract: IssuanceContractMock;
  beforeEach(() => {
    contract = new IssuanceContractMock();
    vi.resetAllMocks();
  });

  it("should allow admin to pause and unpause contract", () => {
    const pauseResult = contract.pauseContract(accounts.deployer);
    expect(pauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: true });

    const issueDuringPause = contract.issueCredential(
      accounts.issuer,
      "did:stack:user-hash",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    expect(issueDuringPause).toEqual({ ok: false, value: 203 });

    const unpauseResult = contract.unpauseContract(accounts.deployer);
    expect(unpauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: false });
  });

  it("should prevent non-admin from pausing", () => {
    const pauseResult = contract.pauseContract(accounts.issuer);
    expect(pauseResult).toEqual({ ok: false, value: 200 });
  });

  it("should allow issuer registration", () => {
    const registerResult = contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    expect(registerResult).toEqual({ ok: true, value: true });
    const issuer = contract.getIssuer(accounts.issuer);
    expect(issuer).toEqual({
      ok: true,
      value: expect.objectContaining({
        name: "Health Clinic",
        active: true,
        verificationKey: "pubkey1",
      }),
    });
  });

  it("should prevent duplicate issuer registration", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const duplicateResult = contract.registerIssuer(accounts.issuer, "Another Clinic", "pubkey2");
    expect(duplicateResult).toEqual({ ok: false, value: 205 });
  });

  it("should allow admin to deactivate issuer", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const deactivateResult = contract.deactivateIssuer(accounts.deployer, accounts.issuer);
    expect(deactivateResult).toEqual({ ok: true, value: true });
    expect(contract.isIssuerActive(accounts.issuer)).toEqual({ ok: true, value: false });
  });

  it("should allow issuer to issue credential", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const did = "did:stack:user-hash";
    const issueResult = contract.issueCredential(
      accounts.issuer,
      did,
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    expect(issueResult.ok).toBe(true);
    const credentialId = issueResult.value as string;
    const credential = contract.getCredential(credentialId);
    expect(credential).toEqual({
      ok: true,
      value: expect.objectContaining({
        did,
        issuer: accounts.issuer,
        vaccineType: "Pfizer",
        batchNumber: "BATCH123",
        metadata: "Vaccination details",
        signature: "signature1",
        active: true,
      }),
    });
    const record = contract.getIssuanceRecord(did, 1);
    expect(record).toEqual({
      ok: true,
      value: expect.objectContaining({ credentialId }),
    });
  });

  it("should prevent non-issuer from issuing credential", () => {
    const issueResult = contract.issueCredential(
      accounts.user,
      "did:stack:user-hash",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    expect(issueResult).toEqual({ ok: false, value: 202 });
  });

  it("should prevent issuing with invalid DID", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const issueResult = contract.issueCredential(
      accounts.issuer,
      "invalid-did",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    expect(issueResult).toEqual({ ok: false, value: 206 });
  });

  it("should allow issuer to revoke credential", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const issueResult = contract.issueCredential(
      accounts.issuer,
      "did:stack:user-hash",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    const credentialId = issueResult.value as string;
    const revokeResult = contract.revokeCredential(accounts.issuer, credentialId);
    expect(revokeResult).toEqual({ ok: true, value: true });
    expect(contract.isCredentialActive(credentialId)).toEqual({ ok: true, value: false });
  });

  it("should prevent non-issuer from revoking credential", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const issueResult = contract.issueCredential(
      accounts.issuer,
      "did:stack:user-hash",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    const credentialId = issueResult.value as string;
    const revokeResult = contract.revokeCredential(accounts.user, credentialId);
    expect(revokeResult).toEqual({ ok: false, value: 202 });
  });

  it("should verify issuer signature", () => {
    contract.registerIssuer(accounts.issuer, "Health Clinic", "pubkey1");
    const issueResult = contract.issueCredential(
      accounts.issuer,
      "did:stack:user-hash",
      "Pfizer",
      "BATCH123",
      Date.now(),
      null,
      "Vaccination details",
      "signature1",
      1
    );
    const credentialId = issueResult.value as string;
    const verifyResult = contract.verifyIssuerSignature(credentialId, "signature1");
    expect(verifyResult).toEqual({ ok: true, value: true });
  });
});