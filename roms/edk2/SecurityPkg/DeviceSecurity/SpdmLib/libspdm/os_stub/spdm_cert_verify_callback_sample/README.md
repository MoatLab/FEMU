## This is reference implementation to verify CertChain DiceTcbInfo extension.

### DiceTcbInfo extension Spec
[DICE Attestation Architecture](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-Version-1.1-Revision-18_pub.pdf)

### Implementation Assumption
   1) **Reference TcbInfo.**

      - Only one reference TcbInfo entry is provided by the integrator. (Multiple reference TcbInfo is NOT supported in this Implementation.)
   2) **Reported TcbInfo**

      - The number of reported TcbInfo must match the number of reference TcbInfo.
   3) **TcbInfo Matching**

      - Each of the reported TcbInfo must fully match each of the reference TcbInfo with same order.
   4) **TcbInfo Field**

      - The reported TcbInfo must include all fields in the reference TcbInfo. If a field in the reference TcbInfo does not exist in the reported  TcbInfo, the verification must fail.
      - The reported TcbInfo could include more fields which do not exist in the reference TcbInfo. The extra fields in the reported TcbInfo must be ignored and NOT validated, and they must not impact the final result.


### Note
   1) To verify the CertChain DiceTcbInfo extension, please use the following command to build.
   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=openssl -DX509_IGNORE_CRITICAL=ON ..
   ```

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=openssl -DX509_IGNORE_CRITICAL=ON ..
   ```
   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=mbedtls -DX509_IGNORE_CRITICAL=ON ..
   ```

   ```
   cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Release -DCRYPTO=mbedtls -DX509_IGNORE_CRITICAL=ON ..
   ```
