unit HCryptoAPI.BigNumber.Primes;

interface

uses
  Velthuis.BigIntegers,
  Velthuis.BigIntegers.Primes,
  Velthuis.RandomNumbers;

function HPrime_GeneratePrime(const Bits: Cardinal; const Probability: Cardinal): BigInteger;
function HPrime_GeneratePrimeExp(const Bits: Cardinal; const Probability: Cardinal): BigInteger;
function HPrime_GeneratePrimeExp_Two(const Bits, Probability: Cardinal): BigInteger;
function HPrime_GeneratePrimeFormularly(const Bits, Probability: Cardinal): BigInteger;
function HPrime_GeneratePrimeExp_Two_Randomized(const Bits, Probability: Cardinal): BigInteger;
function HPrime_GeneratePrimeFormularly_Randomized(const Bits, Probability: Cardinal): BigInteger;

implementation

function HPrime_GeneratePrime(const Bits: Cardinal; const Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits - 1, R);
  repeat
    B := (A shl 1); // A * 2
    Result := B - 3;
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B + 3;
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B - 1;
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B + 1;
    if IsProbablePrime(Result, Probability) then
      break;
    A := A + 1;
  until (false);
//  Result := B;
  R.Free;
end;

function HPrime_GeneratePrimeExp(const Bits: Cardinal; const Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits div 2, R);
  repeat
    B := A.Pow(A, 2); // A ** 2
    Result := B - (A + 1);
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B + (A - 1);
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B - (A - 1);
    if IsProbablePrime(Result, Probability) then
      break;
    Result := B + (A + 1);
    if IsProbablePrime(Result, Probability) then
      break;
    A := A + 1;
  until (false);
//  Result := B;
  R.Free;
end;

function HPrime_GeneratePrimeExp_Two(const Bits, Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits div 2, R);
  repeat
    if IsProbablePrime(A, 1) then begin
      A := A + 1;
      Continue;
    end;
    B := BigInteger.Pow(A, 2) + 1;
    A := A + 1;
  until (IsProbablePrime(B, Probability));
  Result := B;
  R.Free;
end;

function HPrime_GeneratePrimeExp_Two_Randomized(const Bits, Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits div 2, R);
  repeat
    if IsProbablePrime(A, 1) then begin
      A := BigInteger.Create(Bits div 2, R);
      Continue;
    end;
    B := BigInteger.Pow(A, 2) + 1;
    A := BigInteger.Create(Bits div 2, R);
  until (IsProbablePrime(B, Probability));
  Result := B;
  R.Free;
end;

function HPrime_GeneratePrimeFormularly(const Bits, Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  {6k + 1};
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits - 5, R);
  repeat
    if IsProbablePrime(A, 1) then begin
      A := A + 1;
      Continue;
    end;
    B := (A * 6) + 1;
    A := A + 1;
  until (IsProbablePrime(B, Probability));
  Result := B;
  R.Free;
end;

function HPrime_GeneratePrimeFormularly_Randomized(const Bits, Probability: Cardinal): BigInteger;
var A, B: BigInteger;
    R: TRandom;
begin
  {6k + 1};
  R := TRandom.Create(Random(High(Integer) - 1));
  A := BigInteger.Create(Bits - 5, R);
  repeat
    if IsProbablePrime(A, 1) then begin
      A := BigInteger.Create(Bits - 5, R);
      Continue;
    end;
    B := (A * 6) + 1;
    A := BigInteger.Create(Bits - 5, R);
  until (IsProbablePrime(B, Probability));
  Result := B;
  R.Free;
end;

end.
