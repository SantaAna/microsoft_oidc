defmodule MicrosoftOidc.Token do
  @moduledoc """
  Implementation of Joken Token for Microsoft JWTs 
  returned by OIDC.
  """
  use Joken.Config, default_signer: nil

  add_hook(JokenJwks, strategy: Pento.MsftJwksStrategy)

  @impl true
  def token_config() do
    default_claims(skip: [:aud, :iss])
    |> add_claim("aud", nil, &(&1 == Application.fetch_env!(:microsoft_oidc, :msft_client_id)))
  end
end
