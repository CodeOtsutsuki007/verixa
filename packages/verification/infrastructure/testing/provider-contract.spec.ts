import { ManualReviewProvider } from "../providers/manual-review-provider.js";

import { verificationProviderContract } from "./contracts/verification-provider.contract.js";

// The default provider is the only implementation today. The next vendor
// adapter runs this exact suite, which is what makes the port a real
// contract rather than an interface both happen to `implements`.
verificationProviderContract(() => new ManualReviewProvider());
