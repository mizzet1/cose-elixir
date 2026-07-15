defmodule COSETest.OKPKey do
  use ExUnit.Case

  alias COSE.Keys.OKP

  @kty 1
  @crv -1
  @x -2

  describe "OKP.decode/1" do
    test "accepts a valid X25519 COSE_Key map" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => 1, @crv => 4, @x => %CBOR.Tag{tag: :bytes, value: key.x}}

      assert {:ok, parsed} = OKP.decode(cbor_map)
      assert parsed.kty == :okp
      assert parsed.crv == :x25519
      assert parsed.x == key.x
    end

    test "rejects x coordinate of wrong size" do
      cbor_map = %{
        @kty => 1,
        @crv => 4,
        @x => %CBOR.Tag{tag: :bytes, value: :binary.copy(<<0>>, 31)}
      }

      assert {:error, :invalid_cose_key} = OKP.decode(cbor_map)
    end

    test "rejects x coordinate encoded as a CBOR text string instead of a byte string" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => 1, @crv => 4, @x => key.x}

      assert {:error, :invalid_cose_key} = OKP.decode(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = OKP.decode(%{})
    end
  end
end
