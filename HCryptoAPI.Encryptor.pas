unit HCryptoAPI.Encryptor;

interface

uses
  HCryptoAPI.Types,
  HCryptoAPI.Commons;

type
  HCryptoAPI_TEncryptor<TKey> = class(TObject)
  type
    TEncryptionFunction = procedure(var Bytes: TBytesArray; const Key: TKey);
    TDecryptionFunction = procedure(var Bytes: TBytesArray; const Key: TKey);
  public
    class function Encrypt(Algorithm: TEncryptionFunction; const Bytes: TBytesArray; const Key: TKey): TBytesArray; static;
    class function Decrypt(Algorithm: TDecryptionFunction; const Bytes: TBytesArray; const Key: TKey): TBytesArray; static;
end;

implementation

{ HCryptoAPI_TEncryptor<TKey> }

class function HCryptoAPI_TEncryptor<TKey>.Decrypt(Algorithm: TDecryptionFunction; const Bytes: TBytesArray; const Key: TKey): TBytesArray;
begin
  Result := HCrypto_CopyBytes(Bytes);
  Algorithm(Result, Key);
end;

class function HCryptoAPI_TEncryptor<TKey>.Encrypt(Algorithm: TEncryptionFunction; const Bytes: TBytesArray; const Key: TKey): TBytesArray;
begin
  Result := HCrypto_CopyBytes(Bytes);
  Algorithm(Result, Key);
end;

end.
