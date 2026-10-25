"""
KAVACH v2 - Isolated Synthetic Banking Simulator
Provides safe, demonstration banking tools for runtime policy verification.
All customer data and interest rates are purely synthetic.
Simulated export operations record events to a local memory audit log
and NEVER transmit data across the internet.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

# Local audit log of simulated tool actions
SIMULATED_TOOL_AUDIT_LOG: List[Dict[str, Any]] = []

SYNTHETIC_RATES = {
    "savings": "2.70% p.a. for balance up to Rs 10 Lakhs, 3.00% p.a. above Rs 10 Lakhs",
    "fixed_deposit": "6.80% p.a. for 1-year tenure (7.30% for senior citizens)",
    "home_loan": "8.40% p.a. floating interest rate linked to RBI Repo Rate",
    "personal_loan": "10.50% - 14.00% p.a. depending on credit score"
}

SYNTHETIC_CUSTOMER_RECORDS = {
    "CUST_1001": {
        "customer_id": "CUST_1001",
        "name": "Aarav Sharma (SYNTHETIC RECORD)",
        "account_type": "Savings Regular",
        "branch": "Connaught Place, New Delhi",
        "mab_requirement": 3000,
        "kyc_status": "VERIFIED_AADHAAR"
    },
    "CUST_1002": {
        "customer_id": "CUST_1002",
        "name": "Priya Patel (SYNTHETIC RECORD)",
        "account_type": "Current Business",
        "branch": "Bandra Kurla Complex, Mumbai",
        "mab_requirement": 10000,
        "kyc_status": "VERIFIED_PAN"
    }
}


def search_public_documents(query: str) -> Dict[str, Any]:
    """Searches synthetic public banking documentation."""
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": "search_public_documents",
        "query": query,
        "status": "success"
    }
    SIMULATED_TOOL_AUDIT_LOG.append(record)
    return {
        "status": "success",
        "query": query,
        "results": [
            f"Public Policy Index: Matching guidelines for query '{query[:40]}'.",
            "RBI Circular 2024/09: Customer protection in unauthorized electronic banking transactions."
        ]
    }


def retrieve_bank_rates(product: str) -> Dict[str, Any]:
    """Looks up current synthetic banking interest rates."""
    prod_key = product.lower().replace(" ", "_")
    rate_info = SYNTHETIC_RATES.get(prod_key, "Product rate not found. Available products: savings, fixed_deposit, home_loan, personal_loan.")
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": "retrieve_bank_rates",
        "product": product,
        "rate_info": rate_info
    }
    SIMULATED_TOOL_AUDIT_LOG.append(record)
    return {
        "status": "success",
        "product": product,
        "rate": rate_info
    }


def summarize_public_policy(policy_name: str) -> Dict[str, Any]:
    """Summarizes public Indian banking policies."""
    summary = f"Summary for {policy_name}: All transactions comply with RBI CTS-2010 cheque standards and master directions."
    return {
        "status": "success",
        "policy": policy_name,
        "summary": summary
    }


def simulated_customer_record_access(account_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Simulated customer record access. Requires privileged role authorization.
    Returns purely synthetic demonstration records.
    """
    record = SYNTHETIC_CUSTOMER_RECORDS.get(account_id, {
        "customer_id": account_id,
        "name": "Synthetic Customer",
        "account_type": "Savings",
        "kyc_status": "MOCK_ACTIVE"
    })
    SIMULATED_TOOL_AUDIT_LOG.append({
        "timestamp": datetime.utcnow().isoformat(),
        "tool": "simulated_customer_record_access",
        "account_id": account_id,
        "status": "accessed"
    })
    return {
        "status": "success",
        "record": record
    }


def simulated_external_export(destination: str, data_payload: str, export_reason: Optional[str] = None) -> Dict[str, Any]:
    """
    Simulated external export.
    CRITICAL: Never sends data over the internet! Only records the action locally in memory for audit logging.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": "simulated_external_export",
        "destination": destination,
        "payload_length": len(data_payload),
        "export_reason": export_reason,
        "note": "LOCAL SIMULATION AUDIT ONLY - NO INTERNET TRANSMISSION"
    }
    SIMULATED_TOOL_AUDIT_LOG.append(event)
    return {
        "status": "simulated_success",
        "destination": destination,
        "bytes_recorded": len(data_payload),
        "audit_note": "Action logged in local simulator memory. External network was NOT contacted."
    }
