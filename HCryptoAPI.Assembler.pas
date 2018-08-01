unit HCryptoAPI.Assembler;

interface

uses
  HCryptoAPI.Types;

{ Exports functions }

procedure HCrypto_ASM_ROLBYTES(var Buffer: TBytesArray; Amount: Cardinal);
procedure HCrypto_ASM_RORBYTES(var Buffer: TBytesArray; Amount: Cardinal);
procedure HCrypto_ASM_ROLREGS(var Arr: TBytesArray; Bits: Cardinal = 1);
procedure HCrypto_ASM_RORREGS(var Arr: TBytesArray; Bits: Cardinal = 1);
procedure HCrypto_ASM_RORBYTE(var B: Byte; n: cardinal = 1);
procedure HCrypto_ASM_ROLBYTE(var B: Byte; n: cardinal = 1);

implementation

procedure HCrypto_ASM_ROLBYTES(var Buffer: TBytesArray; Amount: Cardinal);
var Len: Cardinal;
    TempBuf: TBytesArray;
begin
  Len := Length(Buffer);
  Amount := Amount mod Len;
  TempBuf := Copy(Buffer, 0, Amount);
  Move(Buffer[Amount], Buffer[0], Len - Amount);
  Move(TempBuf[0], Buffer[Len - Amount], Amount);
end;

procedure HCrypto_ASM_RORBYTES(var Buffer: TBytesArray; Amount: Cardinal);
var Len: Cardinal;
begin
  Len := Length(Buffer);
  Amount := Amount mod Len;
  HCrypto_ASM_ROLBYTES(Buffer, Len - Amount);
end;

procedure HCrypto_ASM_ROLREGS(var Arr: TBytesArray; Bits: Cardinal = 1);
var i,k, Len: Integer;
    x, y, mbt: byte;
begin
  Len := Length(Arr);
  if Len > 0 then begin
    HCrypto_ASM_ROLBYTES(Arr, Bits div 8);
    Bits := Bits mod (8);
    for k := 1 to Bits do begin
      x := Arr[Len-1];
      asm
        shl x, 1;
        jnc @@Equal0;
        mov mbt, 1;
        jmp @@Ext;
        @@Equal0:
          mov mbt, 0;
        @@Ext:
      end;
      Arr[Len-1] := x;
      for i := Len - 2 downto 0 do begin
        x := Arr[i];
        asm
          xor eax, eax;
          shr mbt, 1;
          jnc @@Equal0;
          mov y, 1;
          jmp @@Next;
          @@Equal0:
            mov y, 0;
          @@Next:
            shl x, 1;
            jnc @@Eq0;
            mov mbt, 1;
            jmp @@Nxt;
          @@Eq0:
            mov mbt, 0;
          @@Nxt:
            mov al, [x];
            shr y, 1;
            jnc @@Eq00;
            bts ax, 0;
            jmp @@Ext;
          @@Eq00:
            btr ax, 0;
          @@Ext:
            mov x, al;
        end;
        Arr[i] := x;
      end;
      x := Arr[Len - 1];
      asm
        xor eax, eax;
        mov al, [x];
        shr mbt, 1;
        jnc @@Eq0;
        bts ax, 0;
        jmp @@Ext;
        @@Eq0:
          btr ax, 0;
        @@Ext:
          mov x, al;
      end;
      Arr[Len - 1] := x;
    end;
  end;
end;

procedure HCrypto_ASM_RORREGS(var Arr: TBytesArray; Bits: Cardinal = 1);
var i, k: Integer;
    x, mbt, y: Byte;
begin
  if Length(Arr) > 0 then begin
    HCrypto_ASM_RORBYTES(Arr, Bits div 8);
    Bits := Bits mod (8);
    for k := 1 to Bits do begin
      x := Arr[0];
      asm
        shr x, 1;
        jnc @@Equal0;
        mov mbt, 1;
        jmp @@Ext;
        @@Equal0:
          mov mbt, 0;
        @@Ext:
      end;
      Arr[0] := x;
      for i := 1 to Length(Arr) - 1 do begin
        x := Arr[i];
        asm
          xor eax, eax;
          shr mbt, 1;
          jnc @@Eq0;
          mov y, 1;
          jmp @@Nxt;
          @@Eq0:
            mov y, 0;
          @@Nxt:
            shr x, 1;
            jnc @@Eq00;
            mov mbt, 1;
            jmp @@Next;
          @@Eq00:
            mov mbt, 0;
          @@Next:
            mov al, [x];
            shr y, 1;
            jnc @@Eq000;
            bts ax, 7;
            jmp @@Ext;
          @@Eq000:
            btr ax, 7;
          @@Ext:
            mov x, al;
        end;
        Arr[i] := x;
      end;
      x := Arr[0];
      asm
        xor eax, eax;
        mov al, x;
        shr mbt, 1;
        jnc @@Eq2;
        bts ax, 7;
        jmp @@Ext;
        @@Eq2:
          btr ax, 7;
        @@Ext:
          mov x, al;
      end;
      Arr[0] := x;
    end;
  end;
end;

procedure HCrypto_ASM_RORBYTE(var B: Byte; n: cardinal = 1);
var G, Count: Byte;
begin
  Count := n mod 8;
  g := b;
  asm
    xor eax, eax;
    xor ebx, ebx;
    mov cl, Count;
    mov al, g;
    ror al, cl;
    mov g, al;
  end;
  b := g;
end;

procedure HCrypto_ASM_ROLBYTE(var B: Byte; n: cardinal = 1);
var G, Count: Byte;
begin
  Count := n mod 8;
  g := b;
  asm
    xor eax, eax;
    xor ebx, ebx;
    mov cl, Count;
    mov al, g;
    rol al, cl;
    mov g, al;
  end;
  b := g;
end;

end.
