import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import neo4j
import os
from streamlit_agraph import agraph, Node, Edge, Config


from dotenv import load_dotenv

load_dotenv()

URI = st.secrets['NEO4J_URI']
AUTH = (st.secrets['NEO4J_USERNAME'], st.secrets['NEO4J_PASSWORD'])
QUERY = """
        MATCH (c:Cve)
        MATCH ()-[r:EXPLOIT]->(c)
        RETURN c.cve as id, c.name as name, c.description as description,
        c.detail as detail ,[(c)-[:AFFECT]->(p) | p.product][0] as product,
        COUNT(r) as available_exploits
        """
QUERY_EXPLOIT = """
    MATCH (e:ExploitRepo)
    RETURN e.url as repo, [(e)-[r:EXPLOIT]->(c) | c.cve][0] as cve
"""

@st.cache_data(ttl=60*60)
def read_data(query, rows=1):
    with neo4j.GraphDatabase.driver(URI, auth=AUTH) as driver:
        records, summary, keys = driver.execute_query(query, {"rows":rows})
        return pd.DataFrame(records, columns=keys)

# def build_graph():
#     nodes =[]
#     edges = []
#     config = Config(width=950,
#                 height=750,
#                 directed=True, 
#                 physics=False, 
#                 hierarchical=False,
#                 # **kwargs
#                 )

#     df = read_data(QUERY_EXPLOIT)
#     expl_dict = df.to_dict()

#     # remove duplicates
#     cves =expl_dict['cve'].values()
#     unique_cves = list(dict.fromkeys(cves))
#     for cve in unique_cves:
#         nodes.append(Node(id=cve,title=repo,label=cve,size=25))

#     for idx in expl_dict['repo'].keys():
#         cve = expl_dict['cve'][idx]
#         repo = expl_dict['repo'][idx]

#         nodes.append(Node(id=idx,title=repo,label=repo,size=25))
#         edges.append(Edge(source=idx,target=cve,label="Exploits"))

#     return_value = agraph(nodes=nodes, 
#                       edges=edges, 
#                       config=config)
#     print(return_value)
#     return return_value

def main():
    st.title("CVE Explorer")

    st.header("Raw Data")

    df = read_data(query=QUERY)
    st.dataframe(df)
    # with st.spinner("Loading graph"):
    #     graph = build_graph()
    #     print(graph)
    # st.success("Done")

if __name__ == "__main__":
    main()