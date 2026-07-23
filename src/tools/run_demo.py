import asyncio
from src.tools.tool_registry import get_tool

async def main():
    tool = get_tool("remediation_decision_tool")
    result = await tool.execute({
        "operation": "selectStrategy",
        "params": {
            "cve_id": "CVE-2024-1234",
            "cvss_score": 9.5,
            "component_type": "os_package",
            "environment": "production",
            },
        })
    print(result)
    asyncio.run(main())

