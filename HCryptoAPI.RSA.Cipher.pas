unit HCryptoAPI.RSA.Cipher;

interface

uses
  System.SysUtils,
  System.IOUtils,
  System.Classes,
  System.Types,
  HCryptoAPI.RSA.KeyGen;

type 
  ECryptoRSA_CouldNotConvertKeys = class(Exception);
  ECryptoRSA_ModulusIsDifferent = class(Exception);
  
function HCrypto_RSALoadPublicKeyFromHEX(const ExpString, ModString: String): HCrypto_TRSAPublicKey;
function HCrypto_RSALoadPrivateKeyFromHEX(const ExpString, ModString: String): HCrypto_TRSAPrivateKey;
function HCrypto_RSALoadKeysFromHEX(const PublicExpString, PrivateExpString, ModString: String): HCrypto_TRSAKeys;
function HCrypto_RSALoadKeysFromFiles(const FileNamePrivateKey, FileNamePublicKey: String): HCrypto_TRSAKeys;
  
implementation

function HCrypto_RSALoadPublicKeyFromHEX(const ExpString, ModString: String): HCrypto_TRSAPublicKey;
begin
  try
    Result.Exponent := '0x' + ExpString;
    Result.Modulus := '0x' + ModString;
  except
    on E: Exception do begin 
      raise ECryptoRSA_CouldNotConvertKeys.Create('Cannot convert strings to keys.');
    end;
  end;
end;

function HCrypto_RSALoadPrivateKeyFromHEX(const ExpString, ModString: String): HCrypto_TRSAPrivateKey;
begin 
  try
    Result.Exponent := '0x' + ExpString;
    Result.Modulus := '0x' + ModString;
  except
    on E: Exception do begin
      raise ECryptoRSA_CouldNotConvertKeys.Create('Cannot convert strings to keys.');
    end;
  end;
end;

function HCrypto_RSALoadKeysFromHEX(const PublicExpString, PrivateExpString, ModString: String): HCrypto_TRSAKeys;
begin
  Result.PublicKey := HCrypto_RSALoadPublicKeyFromHEX(PublicExpString, ModString);
  Result.PrivateKey := HCrypto_RSALoadPrivateKeyFromHEX(PrivateExpString, ModString);
end;

function HCrypto_RSALoadKeysFromFiles(const FileNamePrivateKey, FileNamePublicKey: String): HCrypto_TRSAKeys;
var PuStrings, PrStrings: TStringDynArray;
begin
  PuStrings := TFile.ReadAllLines(FileNamePublicKey);
  PrStrings := TFile.ReadAllLines(FileNamePrivateKey);
  Result := HCrypto_RSALoadKeysFromHEX(PuStrings[0], PrStrings[0], PrStrings[1]);
end;

end.
