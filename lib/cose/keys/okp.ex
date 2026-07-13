defmodule COSE.Keys.OKP do
  @moduledoc """
  COSE OKP (Octet Key Pair) key type.

  COSE integer labels follow RFC 9052. After a CBOR round-trip, atom values
  (`:okp`, `:x25519`) come back as binary strings (`"okp"`, `"x25519"`).
  Each clause validates the key material (e.g. coordinate size) as part of
  the parse step, so no separate validation is needed by the caller.
  """

  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

  # COSE Key common parameter labels (RFC 9052 §7.1)
  @kty 1
  @crv -1

  # COSE Key type values (after CBOR round-trip, atoms → strings)
  @kty_okp to_string(:okp)

  # COSE OKP curve values (RFC 9052 §7.2)
  @crv_x25519 to_string(:x25519)

  # COSE OKP key parameter: public key x coordinate
  @x -2

  # Expected byte length of an X25519 public key (RFC 7748 §6.1)
  @x25519_key_size 32

  @doc """
  Parses a decoded COSE_Key map into a typed COSE key struct.

  Dispatches on `kty` and `crv`. Each clause embeds the key-size
  validation for that specific algorithm, so callers do not need a
  separate validation step.

  Returns `{:ok, key}` on success or `{:error, :invalid_cose_key}`.
  """
  @spec from_cbor_map(map()) :: {:ok, %__MODULE__{}} | {:error, :invalid_cose_key}
  def from_cbor_map(%{@kty => @kty_okp, @crv => @crv_x25519, @x => x})
      when is_binary(x) and byte_size(x) == @x25519_key_size do
    {:ok, %__MODULE__{kty: :okp, crv: :x25519, x: x}}
  end

  def from_cbor_map(_), do: {:error, :invalid_cose_key}

  @doc """
  Parses a wire-format COSE_Key map (integer labels, coordinates optionally
  wrapped in `%CBOR.Tag{tag: :bytes}`) into a typed COSE key struct.

  Returns `{:ok, key}` on success or `{:error, :invalid_cose_key}`.
  """
  @spec decode(map()) :: {:ok, %__MODULE__{}} | {:error, :invalid_cose_key}
  def decode(%{@kty => 1, @crv => crv} = cose_key) do
    with {:ok, cose_crv} <- crv_from_label(crv),
         {:ok, x} <- fetch_coord(cose_key, @x) do
      {:ok, %__MODULE__{kty: :okp, crv: cose_crv, x: x}}
    else
      _ -> {:error, :invalid_cose_key}
    end
  end

  def decode(_), do: {:error, :invalid_cose_key}

  defp crv_from_label(4), do: {:ok, :x25519}
  defp crv_from_label(6), do: {:ok, :ed25519}
  defp crv_from_label(_), do: :error

  defp fetch_coord(cose_key, label) do
    case Map.get(cose_key, label) do
      %CBOR.Tag{tag: :bytes, value: bin} when is_binary(bin) -> {:ok, bin}
      bin when is_binary(bin) -> {:ok, bin}
      _ -> :error
    end
  end

  def generate(:enc) do
    {x, d} = :crypto.generate_key(:eddh, :x25519)

    %__MODULE__{
      kty: :okp,
      crv: :x25519,
      x: x,
      d: d
    }
  end

  def generate(:sig) do
    {x, d} = :crypto.generate_key(:eddsa, :ed25519)

    %__MODULE__{
      kty: :okp,
      crv: :ed25519,
      x: x,
      d: d
    }
  end
end

defimpl COSE.Keys.Key, for: COSE.Keys.OKP do
  @kty 1
  @crv -1
  @x -2

  def sign(key, digest_type, to_be_signed) do
    signature = :crypto.sign(:eddsa, digest_type, to_be_signed, [key.d, :ed25519])
    {:ok, signature}
  end

  def verify(ver_key, digest_type, to_be_verified, signature) do
    case :crypto.verify(:eddsa, digest_type, to_be_verified, signature, [ver_key.x, :ed25519]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  def encode(key), do: %{@kty => key.kty, @crv => key.crv, @x => key.x}
end
