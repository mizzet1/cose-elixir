defmodule COSETest do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Headers}

  test "generate okp keys" do
    assert Keys.OKP.generate(:enc).kty == :okp
    assert Keys.OKP.generate(:enc).crv == :x25519
    assert Keys.OKP.generate(:sig).crv == :ed25519
  end

  test "encode ecc key to map" do
    key = Keys.ECC.generate(:es256)
    map = Keys.encode(key)

    assert map[-2] == key.x
    assert map[-3] == key.y
    refute Map.has_key?(map, -4)
  end

  test "encode ecc key to cbor" do
    key = Keys.ECC.generate(:es256)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-2] == key.x
    assert map[-3] == key.y
  end

  test "encode okp key to map" do
    key = Keys.OKP.generate(:sig)
    map = Keys.encode(key)

    assert map[-2] == key.x
    refute Map.has_key?(map, -4)
  end

  test "encode okp key to cbor" do
    key = Keys.OKP.generate(:sig)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-2] == key.x
  end

  test "encode rsa key to map" do
    key = Keys.RSA.generate(:rs256)
    map = Keys.encode(key)

    assert map[-1] == key.n
    assert map[-2] == key.e
    refute Map.has_key?(map, -3)
  end

  test "encode rsa key to cbor" do
    key = Keys.RSA.generate(:rs256)
    {:ok, map, ""} = CBOR.decode(Keys.encode_cbor(key))

    assert map[-1] == key.n
    assert map[-2] == key.e
  end

  test "encode headers" do
    assert Headers.translate(%{alg: :eddsa}) == %{1 => -8}
    assert Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

    assert Headers.tag_phdr(%{alg: :eddsa}) == COSE.tag_as_byte(<<0xA1, 0x01, 0x27>>)
    phdr = Headers.tag_phdr(%{alg: :eddsa})
    assert Headers.decode_phdr(phdr) == {:ok, %{alg: :eddsa}}
  end
end
