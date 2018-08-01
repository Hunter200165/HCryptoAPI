unit HCryptoAPI.BigNumber;

interface

uses
  System.SysUtils,
  Velthuis.BigIntegers,
  Velthuis.BigIntegers.Primes,
  HCryptoAPI.Commons;

function HCrypto_GetRandomBigInteger(const Bits: Cardinal): BigInteger;
function HCrypto_GetRandomPrime(const Bits: Cardinal; const Precision: Integer): BigInteger;

implementation

function HCrypto_GetRandomBigInteger(const Bits: Cardinal): BigInteger;
var Bytes: TBytes;
begin
  Bytes := TBytes(HCrypto_RandomBuffer(Bits div 8));
  Result := BigInteger.Create(Bytes);
end;

function HCrypto_GetRandomPrime(const Bits: Cardinal; const Precision: Integer): BigInteger;
begin
  Result := HCrypto_GetRandomBigInteger(Bits);
  if (Result mod 2) = 0 then
    Result := Result - 1;
  repeat
    Result := Result + 2;
  until IsProbablePrime(Result, Precision);
end;

end.
