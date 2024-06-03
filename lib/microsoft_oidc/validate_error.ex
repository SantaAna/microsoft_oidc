defmodule MicrosoftOidc.ValidateError do
  @moduledoc """
  Reprsents an error when validating the params 
  sent back from the Oauth server.
  """
  defexception [:message]
end
