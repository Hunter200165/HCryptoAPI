unit HCryptoAPI.RSA.KeyGen;

interface

uses
  Velthuis.BigIntegers.Primes,
  Velthuis.BigIntegers,
  HCryptoAPI.BigNumber.Primes;

var
  HCrypto_RSACompositeKey_Bits: Cardinal = 512;
  HCrypto_RSACompositeKey_Probability: Cardinal = 64;
  HCrypto_RSAEncryptionKey_Bits: Cardinal = 16;
  HCrypto_RSAEncryptionKey_Probability: Cardinal = 64;

type
  HCrypto_RSA_RawKeyGen_Callback = procedure;
  HCrypto_RSA_KeyGen_Callback = procedure(const State: Cardinal);

type
  HCrypto_TFactorArray = array of BigInteger;

  HCrypto_TRSAPrime = record
  private
    FFactors: HCrypto_TFactorArray;
    FBits: Cardinal;
    FContent: BigInteger;
//    procedure AddFactor(const Factor: BigInteger);
  public
    property Factors: HCrypto_TFactorArray read FFactors write FFactors;
    property Bits: Cardinal read FBits write FBits;
    property Content: BigInteger read FContent write FContent;

    function HasFactor(const Factor: BigInteger): Boolean;
    function EulerFunction: BigInteger;
  end;

  HCrypto_TRSAPublicKey = record
  private
    FExponent: BigInteger;
    FModulus: BigInteger;
  public
    property Exponent: BigInteger read FExponent write FExponent;
    property Modulus: BigInteger read FModulus write FModulus;

    function Encrypt(const Msg: BigInteger): BigInteger;
    function Verify(const Signature: BigInteger): BigInteger;
  end;

  HCrypto_TRSAPrivateKey = record
  private
    FExponent: BigInteger;
    FModulus: BigInteger;
  public
    property Exponent: BigInteger read FExponent write FExponent;
    property Modulus: BigInteger read FModulus write FModulus;

    function Decrypt(const EncMsg: BigInteger): BigInteger;
    function Sign(const Msg: BigInteger): BigInteger;
  end;

  HCrypto_TRSAKeys = record
  private
    FPublicKey: HCrypto_TRSAPublicKey;
    FPrivateKey: HCrypto_TRSAPrivateKey;
  public
    property PublicKey: HCrypto_TRSAPublicKey read FPublicKey write FPublicKey;
    property PrivateKey: HCrypto_TRSAPrivateKey read FPrivateKey write FPrivateKey;

    class function GenerateKeyPair(const BitSize: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): HCrypto_TRSAKeys; static;
  end;

  HCrypto_RSACallback_KeyGenerated = procedure(const Count, CountNeeded: Integer) of object;
  HCrypto_RSACallback_MainCallback = procedure(const Action: Integer) of object;
  HCrypto_TRSACallbackedKeygen = class(TObject)
  private
    FOnAction: HCrypto_RSACallback_MainCallback;
    FOnKeyGenerated: HCrypto_RSACallback_KeyGenerated;
  public
    const Action_GeneratingP = 0;
    const Action_GeneratingQ = 1;
    const Action_ComputingN = 2;
    const Action_ComputingEulers = 3;
    const Action_GeneratingE = 4;
    const Action_GeneratingD = 5;
    const Action_Checking = 6;
    const Action_GenerationDone = 7;

    property OnKeyGenerated: HCrypto_RSACallback_KeyGenerated read FOnKeyGenerated write FOnKeyGenerated;
    property OnAction: HCrypto_RSACallback_MainCallback read FOnAction write FOnAction;

    procedure RaiseKeyGenerated(const Count, CountOverall: Integer);
    procedure RaiseAction(const Action: Integer);

    function GeneratePrime(const Bits: Cardinal): HCrypto_TRSAPrime;
    function GenerateKeyPair(const Bits: Cardinal): HCrypto_TRSAKeys;
  end;

function HCrypto_RSAGeneratePrime(const Bits: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): BigInteger; overload;
function HCrypto_RSAGenerateTRSAPrime(const Bits: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): HCrypto_TRSAPrime;

implementation

uses
  System.SysUtils;

function HCrypto_RSAGeneratePrime(const Bits: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): BigInteger; overload;
var CompositeKey: BigInteger;
    Keys: Cardinal;
    i: Integer;
begin
  Result := 1;
  Keys := Bits div HCrypto_RSACompositeKey_Bits;
  Randomize;
  for i := 1 to Keys do begin
    CompositeKey := HPrime_GeneratePrimeExp(HCrypto_RSACompositeKey_Bits,
                                            HCrypto_RSACompositeKey_Probability);
    Result := Result * CompositeKey;
    if Assigned(Callback) then
      Callback;
  end;
end;

function HCrypto_RSAGenerateTRSAPrime(const Bits: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): HCrypto_TRSAPrime;
var CompositeKey: BigInteger;
    Keys: Cardinal;
    i: Integer;
begin
  Result.Content := 1;
  Keys := Bits div HCrypto_RSACompositeKey_Bits;
  Randomize;
  SetLength(Result.FFactors, Keys);
  for i := 1 to Keys do begin
    repeat
      CompositeKey := HPrime_GeneratePrimeExp(HCrypto_RSACompositeKey_Bits, HCrypto_RSACompositeKey_Probability);
    until not Result.HasFactor(CompositeKey);
    // Result.AddFactor(CompositeKey);
    Result.Factors[i - 1] := CompositeKey;
    Result.Content := Result.Content * CompositeKey;
    if Assigned(Callback) then
      Callback;
  end;
end;

{ HCrypto_TRSAPrime }

//procedure HCrypto_TRSAPrime.AddFactor(const Factor: BigInteger);
//begin
//  SetLength(FFactors, Length(FFactors) + 1);
//  Factors[Length(FFactors) - 1] := Factor;
//end;

function HCrypto_TRSAPrime.EulerFunction: BigInteger;
var i: Integer;
begin
  Result := 1;
  for i := 0 to Length(Factors) - 1 do
    Result := Result * (Factors[i] - 1);
end;

function HCrypto_TRSAPrime.HasFactor(const Factor: BigInteger): Boolean;
var i: Integer;
begin
  Result := False;
  for i := 0 to Length(Factors) - 1 do
    if Factors[i] = Factor then begin
      Result := True;
      break;
    end;
end;

{ HCrypto_TRSAKeys }

class function HCrypto_TRSAKeys.GenerateKeyPair(const BitSize: Cardinal; Callback: HCrypto_RSA_RawKeyGen_Callback): HCrypto_TRSAKeys;
var PPrime, QPrime: HCrypto_TRSAPrime;
    NComposite, EulerComposite, EPrime, DComposite, SearchNumber: BigInteger;
begin
  PPrime := HCrypto_RSAGenerateTRSAPrime(BitSize div 2, Callback);
  QPrime := HCrypto_RSAGenerateTRSAPrime(BitSize div 2, Callback);
  NComposite := PPrime.Content * QPrime.Content;
  EulerComposite := PPrime.EulerFunction * QPrime.EulerFunction;
  repeat
    EPrime := HPrime_GeneratePrimeExp(HCrypto_RSAEncryptionKey_Bits, HCrypto_RSAEncryptionKey_Probability);
  until (EPrime > 13) and (EPrime < EulerComposite);
  DComposite := BigInteger.ModInverse(EPrime, EulerComposite);
  SearchNumber := (EPrime * DComposite) mod EulerComposite;
  Result.FPublicKey.FExponent := EPrime;
  Result.FPublicKey.FModulus := NComposite;
  Result.FPrivateKey.FExponent := DComposite;
  Result.FPrivateKey.FModulus := NComposite;
end;

{ HCrypto_TRSAPublicKey }

function HCrypto_TRSAPublicKey.Encrypt(const Msg: BigInteger): BigInteger;
begin
  Result := BigInteger.ModPow(Msg, Exponent, Modulus);
end;

function HCrypto_TRSAPublicKey.Verify(const Signature: BigInteger): BigInteger;
begin
  Result := BigInteger.ModPow(Signature, Exponent, Modulus)
end;

{ HCrypto_TRSAPrivateKey }

function HCrypto_TRSAPrivateKey.Decrypt(const EncMsg: BigInteger): BigInteger;
begin
  Result := BigInteger.ModPow(EncMsg, Exponent, Modulus);
end;

function HCrypto_TRSAPrivateKey.Sign(const Msg: BigInteger): BigInteger;
begin
  Result := BigInteger.ModPow(Msg, Exponent, Modulus);
end;

{ HCrypto_TRSACallbackedKeygen }

function HCrypto_TRSACallbackedKeygen.GenerateKeyPair(const Bits: Cardinal): HCrypto_TRSAKeys;
var PPrime, QPrime: HCrypto_TRSAPrime;
    NComposite, EulerComposite, EPrime, DComposite, SearchNumber: BigInteger;
begin
  // P prime
  RaiseAction(Action_GeneratingP);
  PPrime := GeneratePrime(Bits div 2);
  // Q prime
  RaiseAction(Action_GeneratingQ);
  QPrime := GeneratePrime(Bits div 2);
  // N number
  RaiseAction(Action_ComputingN);
  NComposite := PPrime.Content * QPrime.Content;
  // Eulers function
  RaiseAction(Action_ComputingEulers);
  EulerComposite := PPrime.EulerFunction * QPrime.EulerFunction;
  // E Prime
  RaiseAction(Action_GeneratingE);
  repeat
    EPrime := HPrime_GeneratePrimeExp(HCrypto_RSAEncryptionKey_Bits, HCrypto_RSAEncryptionKey_Probability);
  until (EPrime > 13) and (EPrime < EulerComposite);
  // D number
  RaiseAction(Action_GeneratingD);
  DComposite := BigInteger.ModInverse(EPrime, EulerComposite);
  // Checking
  RaiseAction(Action_Checking);
  SearchNumber := (EPrime * DComposite) mod EulerComposite;
  if SearchNumber <> 1 then
    raise Exception.Create('Invalid RSA key is generated.');
  Result.FPublicKey.FExponent := EPrime;
  Result.FPublicKey.FModulus := NComposite;
  Result.FPrivateKey.FExponent := DComposite;
  Result.FPrivateKey.FModulus := NComposite;
  RaiseAction(Action_GenerationDone);
end;

function HCrypto_TRSACallbackedKeygen.GeneratePrime(const Bits: Cardinal): HCrypto_TRSAPrime;
var CompositeKey: BigInteger;
    Keys: Cardinal;
    i: Integer;
begin
  Result.Content := 1;
  Keys := Bits div HCrypto_RSACompositeKey_Bits;
  Randomize;
  SetLength(Result.FFactors, Keys);
  for i := 1 to Keys do begin
    repeat
      CompositeKey := HPrime_GeneratePrimeExp(HCrypto_RSACompositeKey_Bits, HCrypto_RSACompositeKey_Probability);
    until not Result.HasFactor(CompositeKey);
    // Result.AddFactor(CompositeKey);
    Result.Factors[i - 1] := CompositeKey;
    Result.Content := Result.Content * CompositeKey;
    RaiseKeyGenerated(i, Keys);
  end;
end;

procedure HCrypto_TRSACallbackedKeygen.RaiseAction(const Action: Integer);
begin
  if Assigned(Self.OnAction) then
    OnAction(Action);
end;

procedure HCrypto_TRSACallbackedKeygen.RaiseKeyGenerated(const Count, CountOverall: Integer);
begin
  if Assigned(Self.OnKeyGenerated) then
    OnKeyGenerated(Count, CountOverall);
end;

end.
