defmodule COSETest.ECCKey do
  use ExUnit.Case

  alias COSE.Keys.ECC

  @kty 1
  @crv -1
  @x -2
  @y -3

  describe "ECC.decode/1" do
    test "accepts a valid P-256 COSE_Key map" do
      key = ECC.generate(:es256)
      cbor_map = %{@kty => 2, @crv => 1, @x => key.x, @y => key.y}

      assert {:ok, parsed} = ECC.decode(cbor_map)
      assert parsed.kty == :ecc
      assert parsed.crv == :p256
      assert parsed.alg == :es256
      assert parsed.x == key.x
      assert parsed.y == key.y
    end

    test "rejects coordinate of wrong size" do
      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => :binary.copy(<<0>>, 31),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = ECC.decode(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = ECC.decode(%{})
    end
  end
end
