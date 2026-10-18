import os
import sys
import re
import polars as po
import yaml
import json
import logging
import classification_tool.app.detectors.brute_force_detector_runner as bfdr
import classification_tool.app.detectors.data_exfiltration_detector_runner as der
import classification_tool.app.detectors.lateral_movement_detector_runner as lmdr
import classification_tool.app.detectors.privilege_escalation_detector_runner as pedr
import llm_engine.app.Attack_Correlation as atk_corr

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import torch

from llama_index.core import VectorStoreIndex, PromptTemplate, ChatPromptTemplate, StorageContext, load_index_from_storage, Document, Settings
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from llama_index.core.llms import ChatMessage, MessageRole
from llama_index.core.selectors import PydanticMultiSelector
from llama_index.core.query_engine import CitationQueryEngine, RetrieverQueryEngine, RouterQueryEngine
from llama_index.core.node_parser import HierarchicalNodeParser, SentenceSplitter
from llama_index.core.node_parser.relational.hierarchical import get_leaf_nodes
from llama_index.core.storage.docstore import SimpleDocumentStore
from llama_index.core.retrievers import AutoMergingRetriever, RecursiveRetriever, QueryFusionRetriever
from llama_index.llms.groq import Groq
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.response_synthesizers import get_response_synthesizer
from llama_index.retrievers.bm25 import BM25Retriever
from pathlib import Path

logging.getLogger("llama_index.retrievers").setLevel(logging.ERROR)

class Query_LLM:

    @staticmethod
    def _clamp_top_k(desired: int, corpus_size: int) -> int:
        """Cap retrieval k to BM25/vector corpus size; treat -1 as 'use full corpus'."""
        size = max(corpus_size, 1)
        if desired is None or desired < 0:
            return size
        return max(1, min(desired, size))

    '''
    This function takes the user's input query in string format and sets up the main LLM parameters.

    Input: User query
    Returns: None
    '''
    def __init__(self, bias_proxy : list = list()):

        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        Settings.llm = Groq(model="openai/gpt-oss-120b", temperature = 0.0, api_key=os.getenv("GROQ_API_KEY"))
        Settings.embed_model = HuggingFaceEmbedding(model_name="Qwen/Qwen3-Embedding-0.6b", device = self.device)
        self.bias_proxy = bias_proxy
        self.answer = ""

        return
    '''
    This function fetches the attack parameters from the detectors and parses them into readable documents for the LLM to process.

    Input: None
    Returns: None
    '''
    def get_detector_data(self) -> tuple:
        self.atk_docs = {}

        atk_brute_force = bfdr.get_brute_force_attacks(self.bias_proxy)
        self.brute_force_atks = atk_brute_force[0]

        if len(self.brute_force_atks) > 0:
            self.atk_docs["brute_force_attacks"] = [Document(text = f"Attack: Brute-Force Incident\n---\n{yaml.dump(
                                                    json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False)} + \nEnd",
                                                    metadata = {"document_name": f"brute_force_attack_{index + 1}.txt",
                                                                                "attack_type" : "Brute-Force",
                                                                                "user_id" : user_id.group(),
                                                                                "session_id" : session_id.group(),
                                                                                "action" : "login"})
                                                        for index, atk in enumerate(self.brute_force_atks) if len(atk) > 0 and (user_id := re.search(r"u\d+_\w+", atk)) and (session_id := re.search(r"sess\d+", atk))]
            self.num_nodes_brute_force = 10
        else:
            self.atk_docs["brute_force_attacks"] = [Document(text = "No Brute-Force Attacks are Available\nEnd",
                                                    metadata = {"document_name": f"Brute_Force_attack_1.txt",
                                                                                  "attack_type" : "Brute-Force Attack",
                                                                                  "user_id" : "Not Available", "session_id" : "Not Available"})]
            self.num_nodes_brute_force = -1

        #print([yaml.dump(json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False) + "\nEnd" for atk in self.brute_force_atks])

        atk_data_exfiltration = der.get_data_exfiltration_attacks(self.bias_proxy)
        self.data_exfiltration_atks = atk_data_exfiltration[0]

        if len(self.data_exfiltration_atks) > 0:
            self.atk_docs["data_exfiltration_attacks"] = [Document(text = f"Attack_Type: Data-Exfiltration Incident\n---\n{yaml.dump(
                                                        json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False)} + \nEnd",
                                                        metadata = {"document_name": f"data_exfiltration_attack_{index + 1}.txt",
                                                                                        "attack_type" : "Data-Exfiltration",
                                                                                        "user_id" : user_id.group(),
                                                                                        "session_id" : session_id.group(),
                                                                                        "action": "file download"})
                                                            for index, atk in enumerate(self.data_exfiltration_atks) if len(atk) > 0 and (user_id := re.search(r"u\d+_\w+", atk)) and (session_id := re.search(r"sess\d+", atk))]
            self.num_nodes_data_exfil = 10
        else:
            self.atk_docs["data_exfiltration_attacks"] = [Document(text = "No Data_Exfiltration Attacks are Available\nEnd",
                                                            metadata = {"document_name": f"data_exfiltration_attack_1.txt",
                                                                                          "attack_type" : "Data_Exfiltration Attack",
                                                                                          "user_id" : "Not Available", "session_id" : "Not Available"})]
            self.num_nodes_data_exfil = -1

        #print([yaml.dump(json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False) + "\nEnd" for atk in self.data_exfiltration_atks])

        atk_lateral_movement = lmdr.get_lateral_movement_attacks(self.bias_proxy)
        self.lateral_movement_atks = atk_lateral_movement[0]

        if len(self.lateral_movement_atks) > 0:
            self.atk_docs["lateral_movement_attacks"] = [Document(text = f"Attack_Type: Lateral-Movement Incident\n---\n{yaml.dump(
                                                        json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False)} + \nEnd",
                                                        metadata = {"document_name": f"lateral_movement_attack_{index + 1}.txt",
                                                                                        "attack_type" : "Lateral-Movement",
                                                                                        "user_id" : user_id.group(),
                                                                                        "session_id" : session_id.group()})
                                                            for index, atk in enumerate(self.lateral_movement_atks) if len(atk) > 0 and (user_id := re.search(r"u\d+_\w+", atk)) and (session_id := re.search(r"sess\d+", atk))]
            self.num_nodes_lateral_movement = 10
        else:
            self.atk_docs["lateral_movement_attacks"] = [Document(text = "No Lateral-Movement Attacks are Available\nEnd",
                                                            metadata = {"document_name": f"lateral_movement_attack_1.txt",
                                                                                          "attack_type" : "Lateral-Movement Attack",
                                                                                          "user_id" : "Not Available", "session_id" : "Not Available"})]
            self.num_nodes_lateral_movement = -1

        #print("".join([yaml.dump(json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False) + "\nEnd" for atk in self.lateral_movement_atks]))

        atk_privilege_escalation = pedr.get_privilege_escalation_attacks(self.bias_proxy)
        self.privilege_escalation_atks = atk_privilege_escalation[0]

        if len(self.privilege_escalation_atks) > 0:
            self.atk_docs["privilege_escalation_attacks"] = [Document(text = f"Attack_Type: Privilege-Escalation Incident\n---\n{yaml.dump(
                                                            json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False)} + \nEnd",
                                                            metadata = {"document_name": f"privilage_escalation_attack_{index + 1}.txt",
                                                                                        "attack_type" : "Privilege-Escalation",
                                                                                        "user_id" : user_id.group(),
                                                                                        "session_id" : session_id.group()})
                                                            for index, atk in enumerate(self.privilege_escalation_atks) if len(atk) > 0 and (user_id := re.search(r"u\d+_\w+", atk)) and (session_id := re.search(r"sess\d+", atk))]
            self.num_nodes_privilege_escalation = 10
        else:
            self.atk_docs["privilege_escalation_attacks"] = [Document(text = "No Privilege-Escalation Attacks are Available\nEnd",
                                                            metadata = {"document_name": f"privilege_escalation_attack_1.txt",
                                                                                          "attack_type" : "Privilege-Escalation Attack",
                                                                                          "user_id" : "Not Available", "session_id" : "Not Available"})]
            self.num_nodes_privilege_escalation = -1

        #print("".join([yaml.dump(json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False) + "\nEnd" for atk in self.privilege_escalation_atks]))

        original_data = po.concat((atk_brute_force[1], atk_data_exfiltration[1], atk_lateral_movement[1], atk_privilege_escalation[1])).unique()
        self.all_users_department_seniority = {user_id : user_id + f" has a {seniority.upper()} position in the {department.upper()} department"
                                               for user_id, department, seniority in original_data.to_numpy()}

        atk_corr_obj = atk_corr.Attack_Correlation()
        self.correlated_atks = atk_corr_obj.check_correlation(brute_force = self.brute_force_atks, data_exfiltration = self.data_exfiltration_atks,
                                                              lateral_movement = self.lateral_movement_atks, privilege_escalation = self.privilege_escalation_atks)

        if len(self.correlated_atks) > 0:
            self.atk_docs["correlated_attacks"] = [Document(text = f"Attack_Type: Correlated-Chained Attack Incident\n---\n{yaml.dump(
                                                    json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False)} + \nEnd",
                                                    metadata = {"document_name": f"correlated_chained_attack_{index + 1}.txt",
                                                                                    "attack_type" : "Correlated-Chained Attack",
                                                                                    "sub_attack_type" : re.findall(r'"attack_type":\s*"([^"]+)"', atk)[0],
                                                                                    "user_id" : user_id.group(),
                                                                                    "session_id" : session_id.group()})
                                                    for index, atk in enumerate(self.correlated_atks) if len(atk) > 0 and (user_id := re.search(r"u\d+_\w+", atk)) and (session_id := re.search(r"sess\d+", atk))]
            self.num_nodes_correlared_chained = 12
        else:
            self.atk_docs["correlated_attacks"] = [Document(text = "No Correlated or Chained Attacks are Available\nEnd",
                                                  metadata = {"document_name": f"correlated_chained_attack_1.txt",
                                                                                "attack_type" : "Correlated-Chained Attack",
                                                                                "user_id" : "Not Available", "session_id" : "Not Available"})]
            self.num_nodes_correlared_chained = -1

        #print("".join([yaml.dump(json.loads(atk.rstrip("\n\nEnd of Attack\n\n")), default_flow_style=False) + "\nEnd" for atk in self.privilege_escalation_atks]))
        
        return

    '''
    Helper function that sets up the LLM engines for each attack type and the RAG, and injects the embedding for each
    in the appropritate engine.

    Input:   None
    Returns: None
    '''
    def set_params(self):
        '''
        #Directory Editted for Docker
        PROJECT_ROOT = Path(__file__).resolve().parent.parent
        llm_folder = PROJECT_ROOT/ "llama_model"
        '''

        #Directory for CMD Execution
        current_path = Path.cwd()
        llm_folder = str(current_path / "llm_engine" / "llama_model")

        storage_context = StorageContext.from_defaults(persist_dir=f"{llm_folder}")
        self.index = load_index_from_storage(storage_context, embed_model = HuggingFaceEmbedding(model_name="Qwen/Qwen3-Embedding-0.6b", device = self.device))

        rag_prompt = ("You are an expert cybersecurity assistant that ONLY provides mitigation plans for different cyber attacks.\n"
                      "ABSOLUTE RULE: You MUST ALWAYS cite the DOCUMENT with the PAGE NUMBER or the STEP NUMBER or the CHAPTER or the LINK.\n"
                      "ABSOLUTE RULE: You MUST INCLUDE REASONING for each generated mitigation plan.\n"
                      "ABSOLUTE RULE: You MUST END YOUR RESPONSE with exactly ONE SUGGESTED ACTION chosen from: REVOKE_ACCESS, BLOCK_IP, ESCALATE_TO_HUMAN, or MONITOR_ONLY.\n"
                      "You MUST answer the user's query using ONLY the provided context.\n"
                      "If the provided context does not contain the answer, you MUST explicitly state that applicable information can't be provided.\n"
                      "You MUST NOT use any outside knowledge or pre-trained data to fill in the gaps.\n"
                      "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                      "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                      "Context information is below.\n"
                      "---------------------\n"
                      "{context_str}\n"
                      "---------------------\n"
                      "Query: {query_str}\n"
                      "Answer: ")

        rag_query_engine = CitationQueryEngine.from_args(self.index, 
                                                         llm = Groq(model="openai/gpt-oss-20b", temperature = 0.0, api_key=os.getenv("GROQ_API_KEY")),
                                                         similarity_top_k=5, citation_chunk_size=800, citation_chunk_overlap=80,
                                                         citation_qa_template=PromptTemplate(rag_prompt))
        self.rag_llm = QueryEngineTool(
            query_engine=rag_query_engine,metadata=ToolMetadata(
            name="cyber_attacks_mitigation_engine",
            description="CAN ONLY PROVIDE mitigation, remediation, reasoning, and supporting references for cybersecurity incidents, CANNOT generate or retrieve raw attack logs."))

        brute_force_prompt = [ChatMessage(role=MessageRole.SYSTEM,
                              content=("You are an assistant analyzing ONLY brute-force attack logs.\n"
                                       "If the requested information is not explicitly present in the provided logs, state clearly that it is not available.\n"
                                       "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                                       "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                                       "You MUST ALWAYS CHECK YOUR ANSWERS and NEVER miss any information.\n"
                                       "ABSOLUTE RULE: YOU MUST NOT provide any mitigation plans for any attack type or log.\n"
                                       "Log Data Context:\n"
                                       "---------------------\n"
                                       "{context_str}\n"
                                       "---------------------")),
                            ChatMessage(role=MessageRole.USER, content="Query: {query_str}")]

        hybrid_retriever_brute_force = QueryFusionRetriever([self.brute_force_index.as_retriever(similarity_top_k=self.num_nodes_brute_force),
                                                            BM25Retriever.from_defaults(nodes=self.brute_force_leaf_nodes, similarity_top_k=self.num_nodes_brute_force)],
                                                            similarity_top_k=self.num_nodes_brute_force,
                                                            mode = "reciprocal_rerank",
                                                            num_queries=5)
        brute_force_engine = AutoMergingRetriever(vector_retriever=hybrid_retriever_brute_force, storage_context=self.brute_force_storage_context)
        brute_force_retriever = RetrieverQueryEngine.from_args(retriever=brute_force_engine,
                                                               llm = Settings.llm,
                                                               text_qa_template = ChatPromptTemplate(brute_force_prompt))

        data_exfiltration_prompt = [ChatMessage(role=MessageRole.SYSTEM,
                                    content=("You are an assistant analyzing ONLY data-exfiltration attack logs.\n"
                                            "If the requested information is not explicitly present in the provided logs, state clearly that it is not available.\n"
                                            "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                                            "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                                            "You MUST ALWAYS CHECK YOUR ANSWERS and NEVER miss any information.\n"
                                            "ABSOLUTE RULE: YOU MUST NOT provide any mitigation plans for any attack type or log.\n"
                                            "Log Data Context:\n"
                                            "---------------------\n"
                                            "{context_str}\n"
                                            "---------------------")),
                                ChatMessage(role=MessageRole.USER, content="Query: {query_str}")]

        hybrid_retriever_data_exfiltration = QueryFusionRetriever([self.data_exfil_index.as_retriever(similarity_top_k=self.num_nodes_data_exfil),
                                                                  BM25Retriever.from_defaults(nodes=self.data_exfiltration_leaf_nodes, similarity_top_k=self.num_nodes_data_exfil)],
                                                                  similarity_top_k=self.num_nodes_data_exfil,
                                                                  mode = "reciprocal_rerank",
                                                                  num_queries=5)
        data_exfiltration_engine = AutoMergingRetriever(vector_retriever=hybrid_retriever_data_exfiltration, storage_context=self.data_exfiltration_storage_context)
        data_exfiltration_retriever = RetrieverQueryEngine.from_args(retriever=data_exfiltration_engine,
                                                                     llm = Settings.llm,
                                                                     text_qa_template = ChatPromptTemplate(data_exfiltration_prompt))
        
        privilege_escalation_prompt = [ChatMessage(role=MessageRole.SYSTEM,
                                       content=("You are an assistant analyzing ONLY privilege-escalation attack logs.\n"
                                                "If the requested information is not explicitly present in the provided logs, state clearly that it is not available.\n"
                                                "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                                                "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                                                "You MUST ALWAYS CHECK YOUR ANSWERS and NEVER miss any information.\n"
                                                "ABSOLUTE RULE: YOU MUST NOT provide any mitigation plans for any attack type or log.\n"
                                                "Log Data Context:\n"
                                                "---------------------\n"
                                                "{context_str}\n"
                                                "---------------------")),
                                    ChatMessage(role=MessageRole.USER, content="Query: {query_str}")]

        hybrid_retriever_privilege_escalation = QueryFusionRetriever([self.privilege_escalation_index.as_retriever(similarity_top_k=self.num_nodes_privilege_escalation),
                                                                  BM25Retriever.from_defaults(nodes=self.privilege_escalation_leaf_nodes, similarity_top_k=self.num_nodes_privilege_escalation)],
                                                                  similarity_top_k=self.num_nodes_privilege_escalation,
                                                                  mode = "reciprocal_rerank",
                                                                  num_queries=5)
        privilege_escalation_engine = AutoMergingRetriever(vector_retriever=hybrid_retriever_privilege_escalation, storage_context=self.privilege_escalation_storage_context)
        privilege_escalation_retriever = RetrieverQueryEngine.from_args(retriever=privilege_escalation_engine,
                                                                     llm = Settings.llm,
                                                                     text_qa_template = ChatPromptTemplate(privilege_escalation_prompt))

        lateral_movement_prompt = [ChatMessage(role=MessageRole.SYSTEM,
                                   content=("You are an assistant analyzing ONLY lateral-movement attack logs.\n"
                                            "If the requested information is not explicitly present in the provided logs, state clearly that it is not available.\n"
                                            "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                                            "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                                            "You MUST ALWAYS CHECK YOUR ANSWERS and NEVER miss any information.\n"
                                            "ABSOLUTE RULE: YOU MUST NOT provide any mitigation plans for any attack type or log.\n"
                                            "Log Data Context:\n"
                                            "---------------------\n"
                                            "{context_str}\n"
                                            "---------------------")),
                                ChatMessage(role=MessageRole.USER, content="Query: {query_str}")]

        hybrid_retriever_lateral_movement = QueryFusionRetriever([self.lateral_movement_index.as_retriever(similarity_top_k=self.num_nodes_lateral_movement),
                                                                  BM25Retriever.from_defaults(nodes=self.lateral_movement_leaf_nodes, similarity_top_k=self.num_nodes_lateral_movement)],
                                                                  similarity_top_k=self.num_nodes_lateral_movement,
                                                                  mode = "reciprocal_rerank",
                                                                  num_queries=5)

        lateral_movement_engine = AutoMergingRetriever(vector_retriever=hybrid_retriever_lateral_movement, storage_context=self.lateral_movement_storage_context)
        lateral_movement_retriever = RetrieverQueryEngine.from_args(retriever=lateral_movement_engine,
                                                                     llm = Settings.llm,
                                                                     text_qa_template = ChatPromptTemplate(lateral_movement_prompt))

        correlated_chained_prompt = [ChatMessage(role=MessageRole.SYSTEM,
                                    content=("You are an assistant analyzing ONLY correlated or chained attack logs.\n"
                                            "Correlated or Chained attacks are executed with the SAME USER ID and in the SAME SESSION ID.\n"
                                            "If the requested information is not explicitly present in the provided logs, state clearly that it is not available.\n"
                                            "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                                            "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                                            "You MUST ALWAYS CHECK YOUR ANSWERS and NEVER miss any information.\n"
                                            "ABSOLUTE RULE: YOU MUST NOT provide any mitigation plans for any attack type or log.\n"
                                            "Log Data Context:\n"
                                            "---------------------\n"
                                            "{context_str}\n"
                                            "---------------------")),
                                ChatMessage(role=MessageRole.USER, content="Query: {query_str}")]

        hybrid_retriever_correlated_chained = QueryFusionRetriever([self.correlared_chained_index.as_retriever(similarity_top_k=self.num_nodes_correlared_chained),
                                                                  BM25Retriever.from_defaults(nodes=self.correlared_chained_leaf_nodes, similarity_top_k=self.num_nodes_correlared_chained)],
                                                                  similarity_top_k=self.num_nodes_correlared_chained,
                                                                  mode = "reciprocal_rerank",
                                                                  num_queries=8)
        
        correlared_chained_engine = AutoMergingRetriever(vector_retriever=hybrid_retriever_correlated_chained, storage_context=self.correlared_chained_storage_context)
        correlared_chained_retriever = RetrieverQueryEngine.from_args(retriever=correlared_chained_engine,
                                                                     llm = Settings.llm,
                                                                     text_qa_template = ChatPromptTemplate(correlated_chained_prompt))

        self.correlared_chained_llm = QueryEngineTool(
            query_engine=correlared_chained_retriever,
            metadata = ToolMetadata(name = "correlated-chained attack logs retriever",
                                    description=(
                                    "CANNOT provide any mitigation plans or solutions to cybersecurity incidents.\n"
                                    "FETCHES ONLY correlated security events of different attack types.\n"
                                    "ANSWERS questions about ONLY correlated attack types and their sequence of events.\n"
                                    "DETERMINES temporal relationships (before, after, come after, then, later, "
                                    "previously, subsequently, during, while), causal relationships (triggered, "
                                    "led to, followed, preceded, associated) of correlated security events.\n"
                                    "Example Queries:\n"
                                    "Did the successful login follow a brute-force, and did that user then access sensitive files?\n"
                                    "Did the successful login follow a brute-force, and did that user then perform a privelege-escalation?\n"
                                    "Did the successful login follow a brute-force, and did that user then perform a data-exfiltration?\n"
                                    "Did the successful login follow a brute-force, and did that user then perform a lateral-movement?\n"
                                    "What happened after the user performed brute-force attacks?\n"
                                    "What happened after or before the user performed data-exfiltration attacks?\n"
                                    "What happened after or before the user performed privilege-escalation attacks?\n"
                                    "What happened after or before the user performed lateral attacks?\n"
                                    "What happened after or before the user accessed sensitive files?\n"
                                    "What happened after or before the user performed sudo_exec commands?\n"
                                    "What happened after or before the user performed ssh_connect commands?\n"
                                    "What happened after or before the user performed file_download commands?\n"
                                    "What happened after the user performed login commands?\n"
                                    "Are these alerts part of the same attack?\n"
                                    "Was the privilege-escalation attack followed by a data-exfiltration attack?\n"
                                    "Was the data-exfiltration attack followed by a privilege-escalation attack?\n"
                                    "Was a lateral-movement attack followed by a privilege-escalation attack?\n"
                                    "Was a privilege-escalation attack followed by a lateral-movement attack?\n"
                                    "Was a brute-force attack followed by a data-exfiltration attack?\n"
                                    "Was a brute-force attack followed by a privilege-escalation attack?\n"
                                    "Was a brute-force attack followed by a lateral-movement attack?\n"
                                    "Does the same session contain multiple attack types?\n"
                                    "Does the same user conduct different attacks?"
                                )))

        self.privilege_escalation_llm = QueryEngineTool(
            query_engine=privilege_escalation_retriever,
            metadata = ToolMetadata(name = "privilege-escalation attack logs retriever",
                                    description="CAN ONLY be used to fetch data within ONLY the Privilege-Escalation attack logs. CANNOT provide any mitigation plans or solutions to cybersecurity incidents."))

        self.lateral_movement_llm = QueryEngineTool(
            query_engine=lateral_movement_retriever, 
            metadata = ToolMetadata(name = "lateral-movement attack logs retriever",
                                    description="CAN ONLY be used to fetch data within ONLY the Lateral-Movement attack logs. CANNOT provide any mitigation plans or solutions to cybersecurity incidents."))
        
        
        self.brute_force_llm = QueryEngineTool(
            query_engine=brute_force_retriever,
            metadata = ToolMetadata(name = "brute-force attack logs retriever",
                                    description="CAN ONLY be used to fetch data within ONLY the Brute-Force attack logs. CANNOT provide any mitigation plans or solutions to cybersecurity incidents."))

        self.data_exfil_llm = QueryEngineTool(
            query_engine=data_exfiltration_retriever, 
            metadata = ToolMetadata(name = "data-exfiltration attack logs retriever",
                                    description="CAN ONLY be used to fetch data within ONLY the Data-Exfiltration attack logs. CANNOT provide any mitigation plans or solutions to cybersecurity incidents."))

        synthesizer_prompt = ("You are an expert data aggregator. Your task is to combine all information "
                              "from the provided context to answer the user's query.\n"
                              "Context Information:\n"
                              "---------------------\n"
                              "{context_str}\n"
                              "---------------------\n"
                              "Query:\n"
                              "---------------------\n"
                              "{query_str}\n"
                              "---------------------\n"
                              "CRITICAL OUTPUT INSTRUCTIONS:\n"
                              "1. Comprehensive Data: You MUST combine ALL data found in the context.\n" 
                              "2. STRICT Formatting: Output your answer ONLY as PLAIN, SIMPLE TEXT.\n"
                              "3. DO NOT use MARKDOWN or JSON formatting.\n"
                              "4. ABSOLUTE RULE: YOU MUST INCLUDE the keywords REVOKE_ACCESS, BLOCK_IP, ESCALATE_TO_HUMAN, or MONITOR_ONLY ONLY IF they are available in the context.\n"
                              "5. ABSOLUTE RULE: YOU MUST PROVIDE EXPLICIT REFERENCES for all MITIGATION PLANS in the context ONLY IF REFERENCES are available in the context.\n"
                              "6. ABSOLUTE RULE: YOU MUST PROVIDE EXPLICIT REASONING for all MITIGATION PLANS in the context ONLY IF the REASONING is present in the context.\n"
                              "7. ABSOLUTE RULE: YOU MUST NOT PROVIDE any external infromation outside the user query and context.\n"
                              "Answer: ")
                              
        self.router_llm = Groq(model="qwen/qwen3.6-27b", temperature = 0.0, api_key=os.getenv("GROQ_API_KEY"),
                               additional_kwargs={"reasoning_effort": "default"})
        self.synthesizer = get_response_synthesizer(llm = Settings.llm, response_mode="compact_accumulate", text_qa_template = PromptTemplate(synthesizer_prompt))

        #Setting up an LLM for fixing grammar and spelling
        self.sentence_simplifier_prompt = (
                "You are an expert English sentence spelling and grammar corrector.\n"
                "Your job is strictly to CORRECT the grammatical and spelling errors within the provided User Query.\n"
                "YOU MUST NOT attempt to answer, solve, analyze, or respond to the questions or statements within the User Query.\n"
                "Your output MUST ONLY be the newly rewritten query itself.\n"
                "Context Information:\n"
                "---------------------\n"
                "{context_str}\n"
                "---------------------\n"
                "User Query to Correct:\n"
                "---------------------\n"
                "{query_str}\n"
                "---------------------\n\n"
                "CRITICAL OUTPUT INSTRUCTIONS:\n"
                "1. You MUST fix the query to be grammatically correct and spelled properly without altering its meaning.\n"
                "2. Attack types in user query MUST be EXACTLY formatted as: brute-force, data-exfiltration, lateral-movement, and privilege-escalation.\n"
                "3. Attack types in the user query MUST ONLY be formatted if they are explicitly present in the user query.\n"
                "4. ABSOLUTE RULE: Output only the corrected sentence with proper grammar and spelling. DO NOT include introductions, explanations, commentary, or answers.\n"
                "5. ABSOLUTE RULE: The corrected query MUST NOT contain information outside the original query."
            )

        self.english_simplifier_llm = Groq(model="openai/gpt-oss-safeguard-20b", temperature=0.0, api_key=os.getenv("GROQ_API_KEY"))
        self.system_msg_english_simplifier_llm = ChatMessage(role="system", content = self.sentence_simplifier_prompt)
        
        return

    '''
    This function processes the attack documents by vectorizing them into LLM indicies that can be read by the
    main LLM.

    Input: None
    Returns: None
    '''
    def set_llm(self):
        self.get_detector_data()

        text_splitter_map = {
            "1024": SentenceSplitter(chunk_size=1024, chunk_overlap=128, separator="\nEnd"),
            "512":  SentenceSplitter(chunk_size=512,  chunk_overlap=64,  separator="\nEnd"),
            "256":  SentenceSplitter(chunk_size=256,  chunk_overlap=32,  separator="\nEnd"),
            "128":  SentenceSplitter(chunk_size=128,  chunk_overlap=16,  separator="\nEnd"),
        }

        hierarchical_parser = HierarchicalNodeParser.from_defaults(
            node_parser_ids=["1024", "512", "256", "128"],
            node_parser_map=text_splitter_map,
        )

        brute_force_docs = self.atk_docs["brute_force_attacks"]
        data_exfil_docs = self.atk_docs["data_exfiltration_attacks"]
        lateral_movement_docs = self.atk_docs["lateral_movement_attacks"]
        privilege_escalation_docs = self.atk_docs["privilege_escalation_attacks"]
        correlared_chained_docs = self.atk_docs["correlated_attacks"]

        hierarchical_nodes_brute_force = hierarchical_parser.get_nodes_from_documents(brute_force_docs)
        hierarchical_nodes_data_exfiltration = hierarchical_parser.get_nodes_from_documents(data_exfil_docs)
        hierarchical_nodes_lateral_movement = hierarchical_parser.get_nodes_from_documents(lateral_movement_docs)
        hierarchical_nodes_privilege_escalation = hierarchical_parser.get_nodes_from_documents(privilege_escalation_docs)
        hierarchical_nodes_correlated_chained = hierarchical_parser.get_nodes_from_documents(correlared_chained_docs)

        # Docstore holds every node level
        brute_force_docstore = SimpleDocumentStore()
        brute_force_docstore.add_documents(hierarchical_nodes_brute_force)

        data_exfiltration_docstore = SimpleDocumentStore()
        data_exfiltration_docstore.add_documents(hierarchical_nodes_data_exfiltration)

        lateral_movement_docstore = SimpleDocumentStore()
        lateral_movement_docstore.add_documents(hierarchical_nodes_lateral_movement)

        privilege_escalation_docstore = SimpleDocumentStore()
        privilege_escalation_docstore.add_documents(hierarchical_nodes_privilege_escalation)

        correlared_chained_docstore = SimpleDocumentStore()
        correlared_chained_docstore.add_documents(hierarchical_nodes_correlated_chained)

        self.brute_force_storage_context = StorageContext.from_defaults(docstore=brute_force_docstore)
        self.data_exfiltration_storage_context = StorageContext.from_defaults(docstore=data_exfiltration_docstore)
        self.lateral_movement_storage_context = StorageContext.from_defaults(docstore=lateral_movement_docstore)
        self.privilege_escalation_storage_context = StorageContext.from_defaults(docstore=privilege_escalation_docstore)
        self.correlared_chained_storage_context = StorageContext.from_defaults(docstore=correlared_chained_docstore)

        self.brute_force_leaf_nodes = get_leaf_nodes(hierarchical_nodes_brute_force)
        self.data_exfiltration_leaf_nodes = get_leaf_nodes(hierarchical_nodes_data_exfiltration)
        self.lateral_movement_leaf_nodes = get_leaf_nodes(hierarchical_nodes_lateral_movement)
        self.privilege_escalation_leaf_nodes = get_leaf_nodes(hierarchical_nodes_privilege_escalation)
        self.correlared_chained_leaf_nodes = get_leaf_nodes(hierarchical_nodes_correlated_chained)

        self.brute_force_index = VectorStoreIndex(self.brute_force_leaf_nodes, storage_context=self.brute_force_storage_context)
        self.data_exfil_index = VectorStoreIndex(self.data_exfiltration_leaf_nodes, storage_context=self.data_exfiltration_storage_context)
        self.lateral_movement_index = VectorStoreIndex(self.lateral_movement_leaf_nodes, storage_context=self.lateral_movement_storage_context)
        self.privilege_escalation_index = VectorStoreIndex(self.privilege_escalation_leaf_nodes, storage_context=self.privilege_escalation_storage_context)
        self.correlared_chained_index = VectorStoreIndex(self.correlared_chained_leaf_nodes, storage_context=self.correlared_chained_storage_context)

        # BM25 corpus = leaf nodes. Clamp top-k so k never exceeds corpus size
        # (bm25s raises ValueError when k > available scores).
        self.num_nodes_brute_force = self._clamp_top_k(
            self.num_nodes_brute_force, len(self.brute_force_leaf_nodes)
        )
        self.num_nodes_data_exfil = self._clamp_top_k(
            self.num_nodes_data_exfil, len(self.data_exfiltration_leaf_nodes)
        )
        self.num_nodes_lateral_movement = self._clamp_top_k(
            self.num_nodes_lateral_movement, len(self.lateral_movement_leaf_nodes)
        )
        self.num_nodes_privilege_escalation = self._clamp_top_k(
            self.num_nodes_privilege_escalation, len(self.privilege_escalation_leaf_nodes)
        )
        self.num_nodes_correlared_chained = self._clamp_top_k(
            self.num_nodes_correlared_chained, len(self.correlared_chained_leaf_nodes)
        )

        self.set_params()

        return

    '''
    This function assigns specific responsibilities to each sub-LLM model to minimize hallucinations by ensuring that every model performs
    a dedicated task. For example, individual models are responsible for retrieving mitigation plans from the RAG PDF knowledge base, 
    processing brute-force attack scenarios, or analyzing data exfiltration attacks. User queries are first routed through a Router LLM, 
    which identifies the most relevant sub-LLM models, queries one or more of them as needed, and then consolidates their outputs into a single, 
    coherent response.

    Input: None
    Returns: None
    '''
    def query_llm(self, ui_query : str):
        #The query must be at least 10 characters in length
        if len(ui_query) < 10:
            self.answer = "\n\nShort Query!! Query Must have at least 10 Characters.\n\n"
            return

        try:
            #LLM engine to fix grammar mistakes and simplify query.
            self.english_llm_messages = [self.system_msg_english_simplifier_llm, 
                                         ChatMessage(role="user", content = ui_query)]
            response = self.english_simplifier_llm.chat(self.english_llm_messages)
            query_engine = RouterQueryEngine(
                selector=PydanticMultiSelector.from_defaults(llm=self.router_llm),
                query_engine_tools=[self.rag_llm, self.correlared_chained_llm, self.brute_force_llm, self.data_exfil_llm, self.lateral_movement_llm, self.privilege_escalation_llm], 
                summarizer=self.synthesizer,
                verbose=False)
            
            '''
            print("---------------------------------------\n")
            print(response.message.content)
            print("---------------------------------------\n")
            '''

            self.answer = query_engine.query(response.message.content)
            
        except Exception as e:
            #logging.exception("query_llm failed: %s", e)
            self.answer = ("\n\nError Processing Query Attack Type!!!\n"
            "Only Supported Attack Types are:\n"
            "1. Brute-force\n"
            "2. Data-exfiltration\n"
            "3. Privilege-escalation\n"
            "4. Lateral-movement\n"
            "Also Simplify Query and Check LLM parameters.")
            
            return

        return

    '''
    This function processes the final LLM response and checks whether it contains any user ID. 
    If a user ID is found, it retrieves the corresponding user’s seniority level and department 
    within the organization and appends this information to the response.

    Input: None
    Returns: Tuple of the query answer String, and all the cyber attacks' JSON strings
    '''
    def get_query_answer_and_attack_logs(self) -> tuple:
        self.answer = str(self.answer)
        all_unique_users_in_answer = set([user_id.replace("\n", "") for user_id in re.findall(r"u\d+_\w+\n*", self.answer.lower())])
        users_department_seniority_in_answer = [self.all_users_department_seniority[user_id] for user_id in all_unique_users_in_answer]
        users_department_seniority_in_answer = "\n".join(users_department_seniority_in_answer)

        self.answer += ("\n\nUsers' Department and Seniority:\n" + users_department_seniority_in_answer) if len(users_department_seniority_in_answer) > 0  else ""
        self.answer += "\n\nEnd of Query Answer\n\n"

        return self.answer, self.brute_force_atks, self.data_exfiltration_atks, self.lateral_movement_atks, self.privilege_escalation_atks, self.correlated_atks
'''
#Running Example
import time
st = time.time()

#Must be called only once to avoid overhead
llm = Query_LLM()
llm.set_llm()

#Can be called multiple times for different queries
llm.query_llm(ui_query = sys.argv[1])
answer = llm.get_query_answer_and_attack_logs()[0]

et = time.time()
print(answer)

print(f"Time Taken: {et - st} Seconds")

#Test Real-Time Querying Time without Reloading Models
while(1):
    input_str = input("Input Query:  ") 
    #Can be called multiple times for different queries
    st = time.time()
    llm.query_llm(ui_query = input_str)
    answer = llm.get_query_answer_and_attack_logs()[0]
    et = time.time()
    print(answer)

    print(f"\nTime Taken: {et - st} Seconds\n")
'''