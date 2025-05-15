#!/usr/bin/env python3
"""
database_osint.py — FastMCP tool that manages storage of OSINT results in PostgreSQL

This tool provides functionality to:
- Store collected OSINT data in a structured database
- Query existing data by ID or target information
- Update verification status and notes for collected data
- Delete individual entries or clear the entire database
- Retrieve recent search queries with pagination

Dependencies:
- psycopg2-binary (already in requirements.txt)
- fastmcp

Environment variables:
- POSTGRES_DB: Database name (default: osint_db)
- POSTGRES_USER: Database user (default: osint_user)
- POSTGRES_PASSWORD: Database password (default: password)
- POSTGRES_HOST: Database host (default: localhost)
- POSTGRES_PORT: Database port (default: 5432)
"""
from fastmcp import FastMCP
import psycopg2
from psycopg2.extras import Json, DictCursor
import json
import os
import datetime
from typing import Dict, List, Union, Optional, Any

mcp = FastMCP("database")  # tool route will be /database

# Database connection helper functions
def get_db_connection():
    """Get a connection to the PostgreSQL database."""
    db_params = {
        "dbname": os.environ.get("POSTGRES_DB", "osint_db"),
        "user": os.environ.get("POSTGRES_USER", "osint_user"),
        "password": os.environ.get("POSTGRES_PASSWORD", "password"),
        "host": os.environ.get("POSTGRES_HOST", "localhost"),
        "port": os.environ.get("POSTGRES_PORT", "5432")
    }
    return psycopg2.connect(**db_params)

def init_database():
    """Initialize the database schema if it doesn't exist."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Create targets table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id SERIAL PRIMARY KEY,
        target_type VARCHAR(50) NOT NULL,
        target_value VARCHAR(255) NOT NULL,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        UNIQUE (target_type, target_value)
    )
    """)
    
    # Create osint_sources table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS osint_sources (
        id SERIAL PRIMARY KEY,
        source_name VARCHAR(100) NOT NULL,
        source_type VARCHAR(50) NOT NULL,
        description TEXT,
        UNIQUE (source_name)
    )
    """)
    
    # Create osint_data table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS osint_data (
        id SERIAL PRIMARY KEY,
        target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
        source_id INTEGER REFERENCES osint_sources(id) ON DELETE CASCADE,
        data_type VARCHAR(50) NOT NULL,
        data_value JSONB NOT NULL,
        confidence FLOAT,
        collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        verified BOOLEAN DEFAULT FALSE
    )
    """)
    
    # Create index for faster lookups
    cur.execute("CREATE INDEX IF NOT EXISTS idx_osint_data_target_id ON osint_data(target_id)")
    
    conn.commit()
    cur.close()
    conn.close()

@mcp.tool()
def check_database_connection() -> Dict[str, Union[str, bool]]:
    """
    Check if the database connection is properly configured and working.
    
    Returns:
        A dictionary with connection status and database info if successful
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get database info
        cur.execute("SELECT version()")
        db_version = cur.fetchone()[0]
        
        # Initialize the database if needed
        init_database()
        
        # Get table stats
        cur.execute("SELECT COUNT(*) FROM targets")
        target_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM osint_data")
        data_count = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            "status": "connected",
            "db_version": db_version,
            "target_count": target_count,
            "data_count": data_count
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database connection failed: {str(e)}"
        }

@mcp.tool()
def store_osint_data(
    target_type: str,
    target_value: str,
    source_name: str,
    source_type: str,
    data_type: str,
    data_value: Dict[str, Any],
    confidence: float = 1.0,
    notes: Optional[str] = None
) -> Dict[str, Union[str, int]]:
    """
    Store OSINT data for a target in the database.
    
    Args:
        target_type: Type of target (e.g., 'email', 'domain', 'username', 'phone')
        target_value: Value of the target (e.g., 'user@example.com')
        source_name: Name of the data source (e.g., 'holehe', 'mosint')
        source_type: Type of source ('tool', 'website', 'api', etc.)
        data_type: Type of data being stored (e.g., 'breach', 'social_media', 'geolocation')
        data_value: The actual data as a dictionary
        confidence: Confidence score from 0.0 to 1.0
        notes: Optional notes about this data
        
    Returns:
        A dictionary with operation status and record ID
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Ensure database is initialized
        init_database()
        
        # 1. Insert or update target
        cur.execute("""
        INSERT INTO targets (target_type, target_value, notes, last_updated)
        VALUES (%s, %s, %s, NOW())
        ON CONFLICT (target_type, target_value) 
        DO UPDATE SET last_updated = NOW(), notes = COALESCE(%s, targets.notes)
        RETURNING id
        """, (target_type, target_value, notes, notes))
        
        target_id = cur.fetchone()[0]
        
        # 2. Insert or get source
        cur.execute("""
        INSERT INTO osint_sources (source_name, source_type, description)
        VALUES (%s, %s, %s)
        ON CONFLICT (source_name) 
        DO UPDATE SET source_type = %s
        RETURNING id
        """, (source_name, source_type, f"Source: {source_name}", source_type))
        
        source_id = cur.fetchone()[0]
        
        # 3. Insert data
        cur.execute("""
        INSERT INTO osint_data (target_id, source_id, data_type, data_value, confidence)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
        """, (target_id, source_id, data_type, Json(data_value), confidence))
        
        data_id = cur.fetchone()[0]
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"OSINT data stored successfully",
            "target_id": target_id,
            "data_id": data_id
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
            
        return {
            "status": "error",
            "message": f"Failed to store OSINT data: {str(e)}"
        }

@mcp.tool()
def get_osint_data_by_id(data_id: int) -> Dict[str, Any]:
    """
    Retrieve specific OSINT data entry by its ID.
    
    Args:
        data_id: The ID of the OSINT data entry
        
    Returns:
        A dictionary with the OSINT data or error information
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Get the data with relevant information from other tables
        cur.execute("""
        SELECT 
            d.id,
            t.target_type,
            t.target_value,
            s.source_name,
            s.source_type,
            d.data_type,
            d.data_value,
            d.confidence,
            d.collected_at,
            d.verified,
            t.notes
        FROM 
            osint_data d
            JOIN targets t ON d.target_id = t.id
            JOIN osint_sources s ON d.source_id = s.id
        WHERE 
            d.id = %s
        """, (data_id,))
        
        result = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if result:
            # Convert result to a regular dictionary
            data = dict(result)
            
            # Handle datetime objects for JSON serialization
            data['collected_at'] = data['collected_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            return {
                "status": "success",
                "data": data
            }
        else:
            return {
                "status": "error",
                "message": f"No OSINT data found with ID: {data_id}"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve OSINT data: {str(e)}"
        }

@mcp.tool()
def get_osint_data_by_target(
    target_type: str,
    target_value: str,
    data_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve all OSINT data for a specific target.
    
    Args:
        target_type: Type of target (e.g., 'email', 'domain', 'username', 'phone')
        target_value: Value of the target (e.g., 'user@example.com')
        data_type: Optional filter by data type
        
    Returns:
        A dictionary with the OSINT data or error information
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Build the query based on parameters
        query = """
        SELECT 
            d.id,
            t.target_type,
            t.target_value,
            s.source_name,
            s.source_type,
            d.data_type,
            d.data_value,
            d.confidence,
            d.collected_at,
            d.verified
        FROM 
            osint_data d
            JOIN targets t ON d.target_id = t.id
            JOIN osint_sources s ON d.source_id = s.id
        WHERE 
            t.target_type = %s
            AND t.target_value = %s
        """
        
        params = [target_type, target_value]
        
        if data_type:
            query += " AND d.data_type = %s"
            params.append(data_type)
            
        query += " ORDER BY d.collected_at DESC"
        
        cur.execute(query, params)
        
        results = cur.fetchall()
        
        # Get target info
        cur.execute("""
        SELECT id, first_seen, last_updated, notes
        FROM targets
        WHERE target_type = %s AND target_value = %s
        """, (target_type, target_value))
        
        target_info = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if results:
            # Convert results to regular dictionaries
            data_items = []
            for result in results:
                item = dict(result)
                # Handle datetime objects for JSON serialization
                item['collected_at'] = item['collected_at'].strftime('%Y-%m-%d %H:%M:%S')
                data_items.append(item)
                
            target_data = dict(target_info) if target_info else {}
            if target_data:
                target_data['first_seen'] = target_data['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
                target_data['last_updated'] = target_data['last_updated'].strftime('%Y-%m-%d %H:%M:%S')
            
            return {
                "status": "success",
                "target_info": target_data,
                "data_count": len(data_items),
                "data": data_items
            }
        else:
            return {
                "status": "not_found",
                "message": f"No OSINT data found for target: {target_type}:{target_value}"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve OSINT data: {str(e)}"
        }

@mcp.tool()
def delete_osint_data(data_id: int) -> Dict[str, str]:
    """
    Delete a specific OSINT data entry by its ID.
    
    Args:
        data_id: The ID of the OSINT data entry to delete
        
    Returns:
        A dictionary with the operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if data exists
        cur.execute("SELECT id FROM osint_data WHERE id = %s", (data_id,))
        if not cur.fetchone():
            return {
                "status": "error",
                "message": f"No OSINT data found with ID: {data_id}"
            }
        
        # Delete the data
        cur.execute("DELETE FROM osint_data WHERE id = %s", (data_id,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"OSINT data with ID {data_id} deleted successfully"
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
            
        return {
            "status": "error",
            "message": f"Failed to delete OSINT data: {str(e)}"
        }

@mcp.tool()
def delete_target(target_id: int) -> Dict[str, str]:
    """
    Delete a target and all its associated OSINT data.
    
    Args:
        target_id: The ID of the target to delete
        
    Returns:
        A dictionary with the operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if target exists
        cur.execute("SELECT id FROM targets WHERE id = %s", (target_id,))
        if not cur.fetchone():
            return {
                "status": "error",
                "message": f"No target found with ID: {target_id}"
            }
        
        # Get the count of data to be deleted
        cur.execute("SELECT COUNT(*) FROM osint_data WHERE target_id = %s", (target_id,))
        data_count = cur.fetchone()[0]
        
        # Delete the target (cascade will delete associated data)
        cur.execute("DELETE FROM targets WHERE id = %s", (target_id,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"Target with ID {target_id} and {data_count} associated data entries deleted successfully"
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
            
        return {
            "status": "error",
            "message": f"Failed to delete target: {str(e)}"
        }

@mcp.tool()
def clear_database() -> Dict[str, str]:
    """
    Clear all data from the database (dangerous operation).
    
    Returns:
        A dictionary with the operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get counts before deletion
        cur.execute("SELECT COUNT(*) FROM osint_data")
        data_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM targets")
        target_count = cur.fetchone()[0]
        
        # Delete all data
        cur.execute("TRUNCATE osint_data, targets, osint_sources CASCADE")
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"Database cleared successfully. Deleted {target_count} targets and {data_count} data entries."
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
            
        return {
            "status": "error",
            "message": f"Failed to clear database: {str(e)}"
        }

@mcp.tool()
def update_osint_data_verification(data_id: int, verified: bool) -> Dict[str, str]:
    """
    Update the verification status of an OSINT data entry.
    
    Args:
        data_id: The ID of the OSINT data entry
        verified: Whether the data is verified
        
    Returns:
        A dictionary with the operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if data exists
        cur.execute("SELECT id FROM osint_data WHERE id = %s", (data_id,))
        if not cur.fetchone():
            return {
                "status": "error",
                "message": f"No OSINT data found with ID: {data_id}"
            }
        
        # Update verification status
        cur.execute("""
        UPDATE osint_data
        SET verified = %s
        WHERE id = %s
        """, (verified, data_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        status = "verified" if verified else "unverified"
        return {
            "status": "success",
            "message": f"OSINT data with ID {data_id} marked as {status}"
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
            
        return {
            "status": "error",
            "message": f"Failed to update verification status: {str(e)}"
        }

@mcp.tool()
def update_osint_data_notes(data_id: int, notes: str) -> Dict[str, Union[str, int]]:
    """
    Update the notes for a specific OSINT data entry.
    
    Args:
        data_id: The ID of the OSINT data entry
        notes: The new notes to set
        
    Returns:
        A dictionary with operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # First, check if the osint_data entry exists
        cur.execute("SELECT id, target_id FROM osint_data WHERE id = %s", (data_id,))
        result = cur.fetchone()
        
        if not result:
            conn.close()
            return {
                "status": "error",
                "message": f"No OSINT data found with ID: {data_id}"
            }
        
        target_id = result[1]
        
        # Update the notes in the targets table
        cur.execute("""
        UPDATE targets 
        SET notes = %s, last_updated = NOW()
        WHERE id = %s
        RETURNING id
        """, (notes, target_id))
        
        if cur.rowcount == 0:
            conn.rollback()
            conn.close()
            return {
                "status": "error",
                "message": f"Failed to update notes for target ID: {target_id}"
            }
        
        # Mark the data as verified too
        cur.execute("""
        UPDATE osint_data
        SET verified = TRUE
        WHERE id = %s
        RETURNING id
        """, (data_id,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"Notes updated for data ID: {data_id}",
            "data_id": data_id,
            "target_id": target_id
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        
        return {
            "status": "error",
            "message": f"Failed to update notes: {str(e)}"
        }

@mcp.tool()
def update_target_notes(target_id: int, notes: str) -> Dict[str, Union[str, int]]:
    """
    Update the notes for a target.
    
    Args:
        target_id: The ID of the target
        notes: The new notes to set
        
    Returns:
        A dictionary with operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if target exists
        cur.execute("SELECT id FROM targets WHERE id = %s", (target_id,))
        if not cur.fetchone():
            conn.close()
            return {
                "status": "error",
                "message": f"No target found with ID: {target_id}"
            }
        
        # Update the notes
        cur.execute("""
        UPDATE targets 
        SET notes = %s, last_updated = NOW()
        WHERE id = %s
        RETURNING id
        """, (notes, target_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"Notes updated for target ID: {target_id}",
            "target_id": target_id
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        
        return {
            "status": "error",
            "message": f"Failed to update target notes: {str(e)}"
        }

@mcp.tool()
def get_recent_searches(limit: int = 10, offset: int = 0) -> Dict[str, Any]:
    """
    Get a list of recent searches from the database.
    
    Args:
        limit: Maximum number of recent searches to return
        offset: Number of records to skip (for pagination)
        
    Returns:
        A dictionary with recent search information
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Get search queries with pagination
        cur.execute("""
        SELECT t.id as target_id, t.target_value as query, t.first_seen, t.last_updated, t.notes,
               COUNT(d.id) as result_count
        FROM targets t
        JOIN osint_data d ON t.id = d.target_id
        WHERE t.target_type = 'search_query'
        GROUP BY t.id, t.target_value, t.first_seen, t.last_updated, t.notes
        ORDER BY t.last_updated DESC
        LIMIT %s OFFSET %s
        """, (limit, offset))
        
        searches = []
        for row in cur.fetchall():
            search = dict(row)
            # Convert datetime objects to strings for JSON serialization
            search['first_seen'] = search['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
            search['last_updated'] = search['last_updated'].strftime('%Y-%m-%d %H:%M:%S')
            searches.append(search)
        
        # Get total count for pagination
        cur.execute("""
        SELECT COUNT(*) as total_count 
        FROM targets
        WHERE target_type = 'search_query'
        """)
        total_count = cur.fetchone()['total_count']
        
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "searches": searches,
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total_count
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve recent searches: {str(e)}"
        }

@mcp.tool()
def update_osint_data_value(data_id: int, data_value: Dict[str, Any]) -> Dict[str, Union[str, int]]:
    """
    Update the data_value field of an OSINT data entry.
    
    Args:
        data_id: The ID of the OSINT data entry
        data_value: The new data value to set
        
    Returns:
        A dictionary with operation status
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if data exists
        cur.execute("SELECT id FROM osint_data WHERE id = %s", (data_id,))
        if not cur.fetchone():
            conn.close()
            return {
                "status": "error",
                "message": f"No OSINT data found with ID: {data_id}"
            }
        
        # Update the data value
        cur.execute("""
        UPDATE osint_data
        SET data_value = %s, verified = TRUE
        WHERE id = %s
        RETURNING id
        """, (Json(data_value), data_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": f"Data value updated for ID: {data_id}",
            "data_id": data_id
        }
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        
        return {
            "status": "error",
            "message": f"Failed to update data value: {str(e)}"
        }

@mcp.tool()
def list_all_targets() -> Dict[str, Any]:
    """
    Retrieve a list of all targets in the database.
    
    Returns:
        A dictionary with all target information
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Get all targets
        cur.execute("""
        SELECT id, target_type, target_value, first_seen, last_updated, notes
        FROM targets
        ORDER BY id
        """)
        
        targets = cur.fetchall()
        
        result = {
            "status": "success",
            "target_count": len(targets),
            "targets": []
        }
        
        for target in targets:
            target_dict = dict(target)
            # Format dates for JSON
            target_dict['first_seen'] = target_dict['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
            target_dict['last_updated'] = target_dict['last_updated'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Get counts of data for this target
            cur.execute("""
            SELECT data_type, COUNT(*) as count
            FROM osint_data
            WHERE target_id = %s
            GROUP BY data_type
            """, (target['id'],))
            
            data_types = cur.fetchall()
            target_dict['data_summary'] = [dict(dt) for dt in data_types]
            
            result["targets"].append(target_dict)
        
        cur.close()
        conn.close()
        
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve targets: {str(e)}"
        }

@mcp.tool()
def list_all_data() -> Dict[str, Any]:
    """
    Retrieve all OSINT data entries in the database.
    
    Returns:
        A dictionary with all OSINT data entries
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Get all data with join to targets and sources
        cur.execute("""
        SELECT 
            d.id,
            t.target_type,
            t.target_value,
            s.source_name,
            s.source_type,
            d.data_type,
            d.data_value,
            d.confidence,
            d.collected_at,
            d.verified
        FROM 
            osint_data d
            JOIN targets t ON d.target_id = t.id
            JOIN osint_sources s ON d.source_id = s.id
        ORDER BY d.id
        """)
        
        results = cur.fetchall()
        
        cur.close()
        conn.close()
        
        if results:
            # Convert results to regular dictionaries
            data_items = []
            for result in results:
                item = dict(result)
                # Handle datetime objects for JSON serialization
                item['collected_at'] = item['collected_at'].strftime('%Y-%m-%d %H:%M:%S')
                data_items.append(item)
            
            return {
                "status": "success",
                "data_count": len(data_items),
                "data": data_items
            }
        else:
            return {
                "status": "success",
                "message": "No OSINT data found in the database",
                "data_count": 0,
                "data": []
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve OSINT data: {str(e)}"
        }

if __name__ == "__main__":
    mcp.run(transport="stdio")