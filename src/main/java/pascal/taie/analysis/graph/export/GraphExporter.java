/*
 * Tai-e: A Static Analysis Framework for Java
 *
 * Copyright (C) 2022 Tian Tan <tiantan@nju.edu.cn>
 * Copyright (C) 2022 Yue Li <yueli@nju.edu.cn>
 *
 * This file is part of Tai-e.
 *
 * Tai-e is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Tai-e is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Tai-e. If not, see <https://www.gnu.org/licenses/>.
 */

package pascal.taie.analysis.graph.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pascal.taie.World;
import pascal.taie.analysis.ProgramAnalysis;
import pascal.taie.analysis.dataflow.analysis.ReachingDefinition;
import pascal.taie.analysis.dataflow.fact.DataflowResult;
import pascal.taie.analysis.dataflow.fact.SetFact;
import pascal.taie.analysis.graph.cfg.CFG;
import pascal.taie.analysis.graph.cfg.CFGBuilder;
import pascal.taie.analysis.graph.cfg.CFGEdge;
import pascal.taie.config.AnalysisConfig;
import pascal.taie.ir.IR;
import pascal.taie.ir.exp.RValue;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JMethod;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import pascal.taie.util.collection.Maps;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Exports Control Flow Graph (CFG) and Data Flow Graph (DFG) of specified methods to JSON format.
 * <p>
 * Usage example:
 * <pre>
 * java -jar tai-e.jar -cp target/classes -m MainClass \
 *   -a "graph-export=method:&lt;com.example.MyClass: void myMethod(int,java.lang.String)&gt;;output:/path/to/output.json"
 * </pre>
 */
public class GraphExporter extends ProgramAnalysis<Void> {

    public static final String ID = "graph-export";

    private static final Logger logger = LogManager.getLogger(GraphExporter.class);

    /**
     * Method signature to export graphs for.
     */
    private final String methodSignature;

    /**
     * Custom output file path (optional).
     * If null, will use default path: output/graphs/{ClassName}_{methodName}.json
     */
    private final String outputPath;

    /**
     * Default output directory for JSON files (used when outputPath is not specified).
     */
    private final File defaultOutputDir;

    public GraphExporter(AnalysisConfig config) {
        super(config);
        this.methodSignature = getOptions().getString("method");
        this.outputPath = getOptions().getString("output");
        this.defaultOutputDir = new File(World.get().getOptions().getOutputDir(), "graphs");
        if (outputPath == null && !defaultOutputDir.exists()) {
            defaultOutputDir.mkdirs();
        }
    }

    @Override
    public Void analyze() {
        if (methodSignature == null || methodSignature.isEmpty()) {
            logger.error("No method specified. Use 'method' option to specify the method signature.");
            logger.info("Example: -a \"graph-export=method:<com.example.MyClass: void myMethod(int)>\"");
            return null;
        }

        ClassHierarchy hierarchy = World.get().getClassHierarchy();
        JMethod method = hierarchy.getMethod(methodSignature);

        if (method == null) {
            logger.error("Method not found: {}", methodSignature);
            return null;
        }

        if (method.isAbstract() || method.isNative()) {
            logger.error("Cannot analyze abstract or native method: {}", methodSignature);
            return null;
        }

        IR ir = method.getIR();
        if (ir == null) {
            logger.error("IR not available for method: {}", methodSignature);
            return null;
        }

        logger.info("Exporting graphs for method: {}", methodSignature);

        // Build CFG
        CFG<Stmt> cfg = ir.getResult(CFGBuilder.ID);
        Map<String, Object> cfgJson = buildCFGJson(cfg);

        // Build DFG based on reaching definitions
        DataflowResult<Stmt, SetFact<Stmt>> reachDefResult = ir.getResult(ReachingDefinition.ID);
        Map<String, Object> dfgJson = buildDFGJson(ir, reachDefResult);

        // Create combined output
        Map<String, Object> result = Maps.newLinkedHashMap();
        result.put("method", methodSignature);
        result.put("cfg", cfgJson);
        result.put("dfg", dfgJson);

        // Export to JSON file
        File jsonFile = exportToJson(result, method);

        // Export to plain text file
        exportToText(result, jsonFile);

        return null;
    }

    /**
     * Builds JSON representation of Control Flow Graph.
     */
    private Map<String, Object> buildCFGJson(CFG<Stmt> cfg) {
        Map<String, Object> cfgJson = Maps.newLinkedHashMap();

        // Build nodes
        List<Map<String, Object>> nodes = new ArrayList<>();
        
        // Add entry node
        Map<String, Object> entryNode = Maps.newLinkedHashMap();
        entryNode.put("id", "entry");
        entryNode.put("type", "ENTRY");
        entryNode.put("label", "Entry");
        nodes.add(entryNode);

        // Add statement nodes
        for (Stmt stmt : cfg.getIR()) {
            Map<String, Object> node = Maps.newLinkedHashMap();
            node.put("id", "stmt_" + stmt.getIndex());
            node.put("index", stmt.getIndex());
            node.put("type", stmt.getClass().getSimpleName());
            node.put("label", stmt.toString());
            node.put("lineNumber", stmt.getLineNumber());
            
            // Add def/use information
            stmt.getDef().ifPresent(def -> node.put("def", def.toString()));
            Set<RValue> uses = stmt.getUses();
            if (!uses.isEmpty()) {
                List<String> useList = new ArrayList<>();
                for (RValue use : uses) {
                    useList.add(use.toString());
                }
                node.put("uses", useList);
            }
            
            nodes.add(node);
        }

        // Add exit node
        Map<String, Object> exitNode = Maps.newLinkedHashMap();
        exitNode.put("id", "exit");
        exitNode.put("type", "EXIT");
        exitNode.put("label", "Exit");
        nodes.add(exitNode);

        cfgJson.put("nodes", nodes);

        // Build edges
        List<Map<String, Object>> edges = new ArrayList<>();

        for (Stmt stmt : cfg) {
            String sourceId;
            if (cfg.isEntry(stmt)) {
                sourceId = "entry";
            } else if (cfg.isExit(stmt)) {
                continue; // Exit has no outgoing edges
            } else {
                sourceId = "stmt_" + stmt.getIndex();
            }

            for (CFGEdge<Stmt> edge : cfg.getOutEdgesOf(stmt)) {
                Map<String, Object> edgeJson = Maps.newLinkedHashMap();
                edgeJson.put("source", sourceId);
                
                Stmt target = edge.target();
                String targetId;
                if (cfg.isExit(target)) {
                    targetId = "exit";
                } else {
                    targetId = "stmt_" + target.getIndex();
                }
                edgeJson.put("target", targetId);
                edgeJson.put("kind", edge.getKind().toString());
                
                // Add exception information for exceptional edges
                if (edge.isExceptional()) {
                    List<String> exceptions = new ArrayList<>();
                    edge.getExceptions().forEach(e -> exceptions.add(e.getName()));
                    edgeJson.put("exceptions", exceptions);
                }
                
                // Add case value for switch edges
                if (edge.isSwitchCase()) {
                    edgeJson.put("caseValue", edge.getCaseValue());
                }
                
                edges.add(edgeJson);
            }
        }

        cfgJson.put("edges", edges);

        return cfgJson;
    }

    /**
     * Builds JSON representation of Data Flow Graph based on def-use chains.
     */
    private Map<String, Object> buildDFGJson(IR ir, DataflowResult<Stmt, SetFact<Stmt>> reachDefResult) {
        Map<String, Object> dfgJson = Maps.newLinkedHashMap();

        // Build nodes (same as CFG nodes but focused on data flow)
        List<Map<String, Object>> nodes = new ArrayList<>();
        
        for (Stmt stmt : ir) {
            Map<String, Object> node = Maps.newLinkedHashMap();
            node.put("id", "stmt_" + stmt.getIndex());
            node.put("index", stmt.getIndex());
            node.put("type", stmt.getClass().getSimpleName());
            node.put("label", stmt.toString());
            node.put("lineNumber", stmt.getLineNumber());
            
            // Add def information
            stmt.getDef().ifPresent(def -> {
                node.put("def", def.toString());
                if (def instanceof Var v) {
                    node.put("defVar", v.getName());
                }
            });
            
            // Add use information
            Set<RValue> uses = stmt.getUses();
            if (!uses.isEmpty()) {
                List<String> useList = new ArrayList<>();
                List<String> useVars = new ArrayList<>();
                for (RValue use : uses) {
                    useList.add(use.toString());
                    if (use instanceof Var v) {
                        useVars.add(v.getName());
                    }
                }
                node.put("uses", useList);
                if (!useVars.isEmpty()) {
                    node.put("useVars", useVars);
                }
            }
            
            nodes.add(node);
        }

        dfgJson.put("nodes", nodes);

        // Build data flow edges (def-use chains)
        List<Map<String, Object>> edges = new ArrayList<>();

        for (Stmt useStmt : ir) {
            SetFact<Stmt> reachingDefs = reachDefResult.getInFact(useStmt);
            
            for (RValue use : useStmt.getUses()) {
                if (use instanceof Var useVar) {
                    // Find all definitions that reach this use
                    for (Stmt defStmt : reachingDefs) {
                        defStmt.getDef().ifPresent(lhs -> {
                            if (lhs.equals(use)) {
                                Map<String, Object> edge = Maps.newLinkedHashMap();
                                edge.put("source", "stmt_" + defStmt.getIndex());
                                edge.put("target", "stmt_" + useStmt.getIndex());
                                edge.put("variable", useVar.getName());
                                edge.put("type", "DEF_USE");
                                edges.add(edge);
                            }
                        });
                    }
                }
            }
        }

        dfgJson.put("edges", edges);

        return dfgJson;
    }

    /**
     * Exports the result to a JSON file.
     *
     * @return the output file
     */
    private File exportToJson(Map<String, Object> result, JMethod method) {
        File outputFile;
        if (outputPath != null && !outputPath.isEmpty()) {
            // Use user-specified output path
            outputFile = new File(outputPath);
            // Ensure parent directory exists
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
        } else {
            // Use default path
            String className = method.getDeclaringClass().getSimpleName();
            String methodName = method.getName();
            String fileName = sanitizeFileName(className + "_" + methodName) + ".json";
            outputFile = new File(defaultOutputDir, fileName);
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(outputFile, result);
            logger.info("Graph exported to: {}", outputFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to export graph to JSON: {}", e.getMessage());
        }
        return outputFile;
    }

    /**
     * Exports the result to a plain text file with optimized format.
     * The text file is saved alongside the JSON file with .txt extension.
     */
    @SuppressWarnings("unchecked")
    private void exportToText(Map<String, Object> result, File jsonFile) {
        // Determine text output file path (same as JSON but with .txt extension)
        String jsonPath = jsonFile.getAbsolutePath();
        String textPath = jsonPath.endsWith(".json")
                ? jsonPath.substring(0, jsonPath.length() - 5) + ".txt"
                : jsonPath + ".txt";
        File textFile = new File(textPath);

        try (PrintWriter writer = new PrintWriter(new FileWriter(textFile))) {
            // Get data from result map
            String methodSig = (String) result.get("method");
            Map<String, Object> cfg = (Map<String, Object>) result.get("cfg");
            Map<String, Object> dfg = (Map<String, Object>) result.get("dfg");

            List<Map<String, Object>> cfgNodes = (List<Map<String, Object>>) cfg.get("nodes");
            List<Map<String, Object>> cfgEdges = (List<Map<String, Object>>) cfg.get("edges");
            List<Map<String, Object>> dfgEdges = (List<Map<String, Object>>) dfg.get("edges");

            // Build node index map: id -> node
            Map<String, Map<String, Object>> nodeMap = Maps.newLinkedHashMap();
            for (Map<String, Object> node : cfgNodes) {
                nodeMap.put((String) node.get("id"), node);
            }

            // 1. Build CFG mapping (Source -> {Target, Kind})
            Map<String, List<String>> nextHops = Maps.newLinkedHashMap();
            for (Map<String, Object> edge : cfgEdges) {
                String src = (String) edge.get("source");
                String tgt = (String) edge.get("target");
                String kind = (String) edge.get("kind");

                nextHops.computeIfAbsent(src, k -> new ArrayList<>());

                // Simplify jump labels
                String label = switch (kind) {
                    case "IF_TRUE" -> "True";
                    case "IF_FALSE" -> "False";
                    case "RETURN" -> "Exit";
                    case "GOTO" -> "Goto";
                    case "SWITCH_CASE" -> "Case";
                    case "SWITCH_DEFAULT" -> "Default";
                    default -> "Next";
                };

                // Map target ID (map stmt_X to X)
                String tgtIdx;
                if (nodeMap.containsKey(tgt)) {
                    Map<String, Object> tgtNode = nodeMap.get(tgt);
                    Object idx = tgtNode.get("index");
                    tgtIdx = idx != null ? idx.toString() : "Exit";
                } else {
                    tgtIdx = "Exit";
                }
                nextHops.get(src).add(label + ": " + tgtIdx);
            }

            // 2. Build DFG mapping (Target -> [Source Definitions])
            Map<String, Set<String>> dataDeps = Maps.newLinkedHashMap();
            for (Map<String, Object> edge : dfgEdges) {
                String tgt = (String) edge.get("target");
                String src = (String) edge.get("source");

                // Get source node's index
                String srcRef;
                if (nodeMap.containsKey(src)) {
                    Map<String, Object> srcNode = nodeMap.get(src);
                    Object idx = srcNode.get("index");
                    srcRef = idx != null ? idx.toString() : src;
                } else {
                    srcRef = src;
                }

                dataDeps.computeIfAbsent(tgt, k -> new HashSet<>()).add(srcRef);
            }

            // 3. Generate output text
            writer.println("Target Method: " + methodSig);
            writer.println();
            writer.println("IR Code (Format: [ID] Label | {CFG} | {DFG Deps}):");
            writer.println("-".repeat(100));

            // Sort nodes by index
            List<Map<String, Object>> sortedNodes = new ArrayList<>(cfgNodes);
            sortedNodes.sort((a, b) -> {
                Object idxA = a.get("index");
                Object idxB = b.get("index");
                int ia = idxA != null ? ((Number) idxA).intValue() : -1;
                int ib = idxB != null ? ((Number) idxB).intValue() : -1;
                return Integer.compare(ia, ib);
            });

            for (Map<String, Object> node : sortedNodes) {
                String type = (String) node.get("type");
                // Skip ENTRY and EXIT nodes
                if ("ENTRY".equals(type) || "EXIT".equals(type)) {
                    continue;
                }

                String nid = (String) node.get("id");
                Object idxObj = node.get("index");
                int idx = idxObj != null ? ((Number) idxObj).intValue() : -1;

                // Clean label, remove redundant info
                String label = ((String) node.get("label")).replace("\"", "'");
                // Truncate label if too long
                if (label.length() > 60) {
                    label = label.substring(0, 57) + "...";
                }

                // Get flow targets
                List<String> flows = nextHops.getOrDefault(nid, List.of("End"));
                String flow = String.join(", ", flows);
                if (flow.isEmpty()) {
                    flow = "End";
                }

                // Get dependencies
                Set<String> deps = dataDeps.getOrDefault(nid, Set.of());
                String depsStr = deps.isEmpty() ? "None" : String.join(", ", deps);

                // Format line
                String line = String.format("%-3d: %-60s | {%s} | {Uses: %s}",
                        idx, label, flow, depsStr);
                writer.println(line);
            }

            logger.info("Text graph exported to: {}", textFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to export graph to text: {}", e.getMessage());
        }
    }

    /**
     * Sanitizes file name by replacing invalid characters.
     */
    private String sanitizeFileName(String name) {
        return name.replaceAll("[\\\\/:*?\"<>|]", "_");
    }
}

