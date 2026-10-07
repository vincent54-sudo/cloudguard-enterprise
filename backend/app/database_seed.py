from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "pass0123")

def seed_cloud_graph():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    with driver.session() as session:
        # Clear existing graph data
        session.run("MATCH (n) DETACH DELETE n")
        
        # Create cloud resource nodes and attack paths
        session.run("""
            CREATE (internet:Resource {name: 'Internet', type: 'Entry Point'})
            CREATE (ec2:Resource {name: 'Web Server', type: 'EC2 Instance (Public IP)', exposed: true})
            CREATE (iam:Resource {name: 'IAM Role', type: 'Over-permissioned Role', admin_access: true})
            CREATE (db:Resource {name: 'Database', type: 'RDS PostgreSQL (Exposed)', sensitive: true})
            
            CREATE (internet)-[:EXPOSES]->(ec2)
            CREATE (ec2)-[:ASSUMES]->(iam)
            CREATE (iam)-[:CONNECTS_TO]->(db)
        """)
    driver.close()
    print("Cloud graph successfully seeded into Neo4j! 🚀")

if __name__ == "__main__":
    seed_cloud_graph()