"""Payment-rail integration: mirror FraudMesh payment outcomes onto PayPal (sandbox) or an offline PayPal mock."""
from api.payments.rails import MockPayPalRail, PaymentRail, PayPalSandboxRail, RailError
from api.payments.service import PaymentDispatcher, RailConfig, rail_from_env


def build_dispatcher(store) -> PaymentDispatcher:
    config, rail = rail_from_env()
    return PaymentDispatcher(store, config, rail)


__all__ = ["MockPayPalRail", "PaymentDispatcher", "PaymentRail", "PayPalSandboxRail", "RailConfig", "RailError",
           "build_dispatcher", "rail_from_env"]
