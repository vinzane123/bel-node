module.exports = {
  SEND: 0, // XAS TRANSFER
  SIGNATURE: 1, // SETUP SECOND_PASSWORD
  DELEGATE: 2, // SECOND_PASSWORD
  VOTE: 3, // VOTE FOR DELEGATE
  MULTI: 4, // MULTISIGNATURE
  DAPP: 5, // DAPP REGISTER
  IN_TRANSFER: 6, // DAPP DEPOSIT
  OUT_TRANSFER: 7, // DAPP WITHDRAW
  STORAGE: 8, // UPLOAD STORAGE

  // UIA: USER ISSUE ASSET
  UIA_ISSUER: 9, // UIA ISSUER REGISTER
  UIA_ASSET: 10, // UIA ASSET REGISTER
  UIA_FLAGS: 11, // UIA FLAGS UPDATE
  UIA_ACL: 12, // UIA ACL UPDATE
  UIA_ISSUE: 13, // UIA ISSUE
  UIA_TRANSFER: 14, // UIA TRANSFER

  //verify Account
  ENABLE_WALLET_KYC:15, // VERIFY KYC STATUS ON THE BLOCKCHAIN SIDE
  DISABLE_WALLET_KYC: 16, // DISABLE KYC STATUS
  WHITELIST_WALLET_TRS: 17, // WHITE LIST BEL & NON-BEL WALLETS
  DOCUMENT_VERIFICATION_TRS: 18,  // INITIAL TRANSACTION WITHOUT VERIFICATION
  WHITELIST_MERCHANT_WALLET_TRS: 19,  // MERCHANT CAN ATTACH ANY SUB WALLET TO THE USER W.R.T. THE SAME COUNTRY
  MERCHANT_TRS: 20,
  MERCHANT: 21,

  LOCK: 100 // ACCOUNT LOCK
}