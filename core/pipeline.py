"""
Multi-Agent Execution Pipeline & Directed Acyclic Graph (DAG) Coordinator.
Executes autonomous agent swarms with dynamic VRAM swapping and context accumulation.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from core.config import AGENT_MODELS
from core.message_bus import message_bus, AgentEvent
from core.model_manager import model_manager
from agents.orchestrator_agent import OrchestratorAgent
from agents.osint_agent import OSINTAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.coding_agent import CodingAgent
from agents.malware_agent import MalwareAgent
from agents.network_agent import NetworkAgent
from agents.report_agent import ReportAgent
from agents.redteam_agent import RedTeamAgent

logger = logging.getLogger("CyberAgent.Pipeline")


class AgentPipeline:
    """Manages multi-agent execution workflow."""

    def __init__(self):
        self.agents: Dict[str, Any] = {
            "orchestrator": OrchestratorAgent(),
            "osint": OSINTAgent(),
            "threat_intel": ThreatIntelAgent(),
            "coder": CodingAgent(),
            "malware": MalwareAgent(),
            "network": NetworkAgent(),
            "report": ReportAgent(),
            "redteam": RedTeamAgent(),
        }

    def get_agent(self, agent_id: str):
        return self.agents.get(agent_id)

    def execute(
        self,
        query: str,
        custom_agents: Optional[List[str]] = None,
        on_token: Optional[Any] = None,
        initial_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute full multi-agent swarm on a user query.
        """
        start_time = time.time()
        logger.info(f"Initiating pipeline for query: '{query}'")

        # Step 1: Determine agent execution plan
        orchestrator: OrchestratorAgent = self.agents["orchestrator"]
        if custom_agents and len(custom_agents) > 0:
            agent_plan = [a for a in custom_agents if a in self.agents]
        else:
            agent_plan = orchestrator.plan_workflow(query)

        total_steps = len(agent_plan)
        logger.info(f"Planned Agent Pipeline: {agent_plan} ({total_steps} stages)")

        # Emit Pipeline Start
        message_bus.emit_sync(
            AgentEvent(
                event_type="pipeline_start",
                agent_id="orchestrator",
                agent_name=orchestrator.name,
                payload={"query": query, "plan": agent_plan, "total_steps": total_steps},
                step_index=0,
                total_steps=total_steps,
            )
        )

        stage_results: List[Dict[str, Any]] = []
        accumulated_context = [initial_context] if initial_context else []

        # Execute each agent sequentially with context passing
        for idx, agent_id in enumerate(agent_plan, 1):
            agent = self.agents.get(agent_id)
            if not agent:
                continue

            current_context = "\n\n".join(accumulated_context)

            logger.info(f"[{idx}/{total_steps}] Running Agent: {agent.name} ({agent.model})...")

            # Route to specialized execution methods if applicable
            if agent_id == "osint":
                res = agent.execute_recon(query, step_index=idx, total_steps=total_steps)
            elif agent_id == "threat_intel":
                res = agent.analyze_threat(query, context=current_context, step_index=idx, total_steps=total_steps)
            elif agent_id == "coder":
                res = agent.generate_security_code(query, context=current_context, step_index=idx, total_steps=total_steps)
            elif agent_id == "malware":
                res = agent.analyze_binary(query, context=current_context, step_index=idx, total_steps=total_steps)
            elif agent_id == "network":
                res = agent.analyze_network_traffic(query, context=current_context, step_index=idx, total_steps=total_steps)
            elif agent_id == "redteam":
                res = agent.execute_tactical_plan(query, context=current_context, step_index=idx, total_steps=total_steps)
            elif agent_id == "report":
                res = agent.generate_report(query, swarm_context=current_context, step_index=idx, total_steps=total_steps)
            else:
                res = agent.run(query, context=current_context, step_index=idx, total_steps=total_steps)

            stage_results.append(res)

            # Append agent findings to shared context
            agent_output = res.get("output", "")
            if agent_output:
                accumulated_context.append(f"### [AGENT: {agent.name}]:\n{agent_output}")

        total_duration = round(time.time() - start_time, 2)

        # Emit Pipeline Complete
        message_bus.emit_sync(
            AgentEvent(
                event_type="pipeline_complete",
                agent_id="orchestrator",
                agent_name=orchestrator.name,
                payload={
                    "total_duration_s": total_duration,
                    "stages_completed": len(stage_results),
                },
                step_index=total_steps,
                total_steps=total_steps,
            )
        )

        return {
            "query": query,
            "agent_plan": agent_plan,
            "total_duration_s": total_duration,
            "stages": stage_results,
            "final_report": stage_results[-1].get("output", "") if stage_results else "",
            "gpu_status": model_manager.get_gpu_stats().to_dict(),
        }


# Global pipeline instance
pipeline = AgentPipeline()
