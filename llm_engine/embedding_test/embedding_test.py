#To run the file, enter branch root directory and run in PowerShell the command
#python -m llm_engine.embedding_test.embedding_test

import os
import sys
import numpy as np
from pathlib import Path
from llama_index.core import PromptTemplate, StorageContext, load_index_from_storage
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from llama_index.core.query_engine import CitationQueryEngine
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.callbacks import CallbackManager, CBEventType, EventPayload
from llama_index.llms.groq import Groq

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import torch

class Test_Ranking_Embedding():

    def __init__(self):
        
        self.api_key = os.getenv("GROQ_API_KEY")
        self.cpu_gpu = "cuda" if torch.cuda.is_available() else "cpu"
        
        #Directory for RAG Embedding
        current_path = Path.cwd()
        self.embed_folder = str(current_path / "llm_engine" / "llama_model")

    def load_embedding(self) -> None:

        if Path(self.embed_folder).exists():
            storage_context = StorageContext.from_defaults(persist_dir=f"{self.embed_folder}")
            self.embedding_model = HuggingFaceEmbedding(model_name="Qwen/Qwen3-Embedding-0.6b", device = self.cpu_gpu)
            self.index = load_index_from_storage(storage_context, embed_model = self.embedding_model)
        else:
            print("ERROR: Embedding Folder Path is Wrong!!")
            sys.exit(1)
            
        return

    def get_embedding_data(self, user_query : str = "") -> str:

        embed_data_str = "\n\nEmbedding Dimension and Vectors:\n\n"
        query_embedding = self.embedding_model.get_query_embedding(user_query)
        embed_data_str += f"Embedding Dimension: {len(query_embedding)}\n"
        embed_data_str += f"First 5 Vectorized Values: {" ,".join(np.array(query_embedding[:5], dtype = str))}\n"

        return embed_data_str

    def get_ranks_similarity(self, user_query : str = "") -> str:
        
        top_5_ranks_str = "\n\nSimilarity and Ranking:\n\n"
        retriever = self.index.as_retriever(similarity_top_k=5, vector_store_query_mode="mmr", vector_store_kwargs={"mmr_threshold": 0.0})
        nodes = retriever.retrieve(user_query)
        top_5_ranks_str += str(nodes) + "\n"

        top_5_ranks_str = "\n\nTop-5 Retrieved Chunks:\n\n"
        for i, node in enumerate(nodes, 1):
            top_5_ranks_str += f"\033[1mRank:\033[0m {i}\n"
            top_5_ranks_str += f"\033[1mSimilarity:\033[0m {node.score}\n"
            top_5_ranks_str += f"\033[1mMetadata:\033[0m {node.node.metadata}\n"
            top_5_ranks_str += f"\033[1mChunk Text:\033[0m {node.node.text}\n\n"

        return top_5_ranks_str
        
    def query_llm(self, user_query : str = "") -> str:
        answer = "\n\nLLM Answer:\n\n"
        query = user_query

        rag_prompt = ("You are an expert cybersecurity assistant that ONLY provides mitigation plans for different cyber attacks.\n"
                      "You MUST INCLUDE REASONING for each generated mitigation plan.\n"
                      "You MUST ALWAYS cite the DOCUMENT with the PAGE NUMBER or the STEP NUMBER or the CHAPTER or the LINK.\n"
                      "You must answer the user's query using ONLY the provided context.\n"
                      "If the provided context does not contain the answer, you MUST explicitly state that applicable information can't be provided.\n"
                      "You are NOT allowed to use any outside knowledge or pre-trained data to fill in the gaps.\n"
                      "You MUST generate answers ONLY in SIMPLE TEXT FORMAT.\n"
                      "You MUST NOT generate answers in MARKDOWN and JSON formats.\n"
                      "Context information is below.\n"
                      "---------------------\n"
                      "{context_str}\n"
                      "---------------------\n"
                      "User Query: {query_str}\n"
                      "Answer: ")
        try:
            rag_query_engine = CitationQueryEngine.from_args(self.index, 
                                                            llm = Groq(model="openai/gpt-oss-120b", temperature = 0.0, api_key=self.api_key),
                                                            similarity_top_k=5, citation_qa_template=PromptTemplate(rag_prompt))

            answer += str(rag_query_engine.query(user_query)) + "\n\n"

        except:
            print("ERROR: Processing LLM Query!!")
            sys.exit(1)

        return answer
'''
if len(sys.argv) > 1 and len(sys.argv[1]) >= 10:
'''
txt_emb = Test_Ranking_Embedding()
txt_emb.load_embedding()

#user_query = sys.argv[1]

#Query 1: What are the mitigation plans for brute-force attacks?
print("\n\n\033[1mQuery 1: What are the mitigation plans for brute-force attacks?\033[0m\n\n")
user_query = "What are the mitigation plans for brute-force attacks?"
print(txt_emb.get_embedding_data(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.get_ranks_similarity(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.query_llm(user_query))


print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)


#Query 2: What are the mitigation plans for data-exfiltration attacks?
print("\n\n\033[1mQuery 2: What are the mitigation plans for data-exfiltration attacks?\033[0m\n\n")
user_query = "What are the mitigation plans for data-exfiltration attacks?"
print(txt_emb.get_embedding_data(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.get_ranks_similarity(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.query_llm(user_query))


print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)


#Query 3: What are the mitigation plans for SQL injection attacks?
print("\n\n\033[1mQuery 3: What are the mitigation plans for SQL injection attacks?\033[0m\n\n")
user_query = "What are the mitigation plans for SQL injection attacks?"
print(txt_emb.get_embedding_data(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.get_ranks_similarity(user_query))
print("\033[1m---------------------------------------------\033[0m\n" * 3)

print(txt_emb.query_llm(user_query))


print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)
print("\033[1m---------------------------------------------\033[0m\n" * 3)

'''
else:
    print("User Query Must Be At least 10 Characters Long!!")
    sys.exit(1)
'''