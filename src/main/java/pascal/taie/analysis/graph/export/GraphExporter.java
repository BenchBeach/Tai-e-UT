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
import pascal.taie.ir.exp.InvokeExp;
import pascal.taie.ir.exp.InvokeInstanceExp;
import pascal.taie.ir.exp.RValue;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.proginfo.MethodRef;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JMethod;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import pascal.taie.util.collection.Maps;
import pascal.taie.util.collection.Sets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Exports Control Flow Graph (CFG), Data Flow Graph (DFG), and Call Chain
 * of specified methods to JSON format.
 * <p>
 * The call chain analysis recursively explores up to 3 levels of method calls.
 * <p>
 * Usage example:
 * <pre>
 * java -jar tai-e.jar -cp target/classes -m MainClass \
 *   -a "graph-export=method:&lt;com.example.MyClass: void myMethod(int,java.lang.String)&gt;;output:/path/to/output/dir"
 * </pre>
 * <p>
 * Options:
 * <ul>
 *   <li>method: Method signature to analyze (required)</li>
 *   <li>output: Output directory path (optional, defaults to {outputDir}/graphs/)</li>
 * </ul>
 */
public class GraphExporter extends ProgramAnalysis<Void> {

    public static final String ID = "graph-export";

    private static final Logger logger = LogManager.getLogger(GraphExporter.class);

    /**
     * Method signature to export graphs for.
     */
    private final String methodSignature;

    /**
     * Output directory for graph files.
     * If specified via 'output' option, uses that directory.
     * Otherwise, uses default: {outputDir}/graphs/
     */
    private final File outputDir;

    public GraphExporter(AnalysisConfig config) {
        super(config);
        this.methodSignature = getOptions().getString("method");
        String outputPath = getOptions().getString("output");
        if (outputPath != null && !outputPath.isEmpty()) {
            this.outputDir = new File(outputPath);
        } else {
            this.outputDir = new File(World.get().getOptions().getOutputDir(), "graphs");
        }
        if (!outputDir.exists()) {
            outputDir.mkdirs();
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

        // Build Call Chain (method invocation graph)
        Map<String, Object> callChainJson = buildCallChainJson(ir);

        // Create combined output
        Map<String, Object> result = Maps.newLinkedHashMap();
        result.put("method", methodSignature);
        result.put("cfg", cfgJson);
        result.put("dfg", dfgJson);
        result.put("callChain", callChainJson);

        // Export to JSON file
        File jsonFile = exportToJson(result, method);

        // Export to plain text file
        exportToText(result, jsonFile);

        // Export call chain to separate prompt-friendly text file
        exportCallChainForPrompt(result, jsonFile);

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
     * Maximum depth for recursive call chain analysis.
     */
    private static final int MAX_CALL_DEPTH = 3;

    /**
     * Builds JSON representation of Call Chain (method invocations within the method).
     * This captures all method calls and their relationships, forming a call graph.
     * Recursively analyzes up to MAX_CALL_DEPTH levels deep.
     */
    private Map<String, Object> buildCallChainJson(IR ir) {
        Set<String> visitedMethods = Sets.newHybridSet();
        return buildCallChainJsonRecursive(ir.getMethod(), 0, visitedMethods);
    }

    /**
     * Recursively builds call chain JSON for a method up to the specified depth.
     *
     * @param method the method to analyze
     * @param currentDepth current recursion depth (0 = target method)
     * @param visitedMethods set of already visited method signatures to avoid cycles
     * @return the call chain JSON representation
     */
    private Map<String, Object> buildCallChainJsonRecursive(
            JMethod method, int currentDepth, Set<String> visitedMethods) {

        Map<String, Object> callChainJson = Maps.newLinkedHashMap();

        // Caller information
        Map<String, Object> callerInfo = Maps.newLinkedHashMap();
        callerInfo.put("signature", method.getSignature());
        callerInfo.put("className", method.getDeclaringClass().getName());
        callerInfo.put("methodName", method.getName());
        callerInfo.put("returnType", method.getReturnType().toString());
        callerInfo.put("depth", currentDepth);
        callChainJson.put("caller", callerInfo);

        // Mark this method as visited
        visitedMethods.add(method.getSignature());

        // Check if we can analyze this method
        if (method.isAbstract() || method.isNative()) {
            callChainJson.put("callSites", new ArrayList<>());
            callChainJson.put("totalCalls", 0);
            callChainJson.put("note", "Cannot analyze abstract or native method");
            return callChainJson;
        }

        IR ir = method.getIR();
        if (ir == null) {
            callChainJson.put("callSites", new ArrayList<>());
            callChainJson.put("totalCalls", 0);
            callChainJson.put("note", "IR not available");
            return callChainJson;
        }

        // Build call sites (invocations)
        List<Map<String, Object>> callSites = new ArrayList<>();
        int callIndex = 0;

        for (Stmt stmt : ir) {
            if (stmt instanceof Invoke invoke) {
                Map<String, Object> callSite = Maps.newLinkedHashMap();
                callSite.put("callIndex", callIndex++);
                callSite.put("stmtIndex", stmt.getIndex());
                callSite.put("lineNumber", stmt.getLineNumber());
                callSite.put("statement", stmt.toString());
                callSite.put("depth", currentDepth);

                InvokeExp invokeExp = invoke.getInvokeExp();
                MethodRef methodRef = invokeExp.getMethodRef();

                // Callee information
                Map<String, Object> calleeInfo = Maps.newLinkedHashMap();
                calleeInfo.put("signature", methodRef.toString());
                calleeInfo.put("className", methodRef.getDeclaringClass().getName());
                calleeInfo.put("methodName", methodRef.getName());
                calleeInfo.put("returnType", methodRef.getReturnType().toString());

                // Parameter types
                List<String> paramTypes = new ArrayList<>();
                for (var paramType : methodRef.getParameterTypes()) {
                    paramTypes.add(paramType.toString());
                }
                calleeInfo.put("parameterTypes", paramTypes);

                // Check if method can be resolved
                JMethod resolvedMethod = methodRef.resolveNullable();
                calleeInfo.put("resolved", resolvedMethod != null);
                if (resolvedMethod != null) {
                    calleeInfo.put("isAbstract", resolvedMethod.isAbstract());
                    calleeInfo.put("isNative", resolvedMethod.isNative());
                    calleeInfo.put("isStatic", resolvedMethod.isStatic());
                }

                callSite.put("callee", calleeInfo);

                // Invoke type
                String invokeType = getInvokeType(invoke);
                callSite.put("invokeType", invokeType);

                // Base variable (for instance invokes)
                if (invokeExp instanceof InvokeInstanceExp instanceExp) {
                    Var base = instanceExp.getBase();
                    callSite.put("baseVar", base.getName());
                }

                // Arguments
                List<Map<String, Object>> args = new ArrayList<>();
                List<Var> argVars = invokeExp.getArgs();
                for (int i = 0; i < argVars.size(); i++) {
                    Map<String, Object> arg = Maps.newLinkedHashMap();
                    arg.put("index", i);
                    arg.put("name", argVars.get(i).getName());
                    arg.put("type", argVars.get(i).getType().toString());
                    args.add(arg);
                }
                callSite.put("arguments", args);

                // Result variable (if any)
                Var result = invoke.getResult();
                if (result != null) {
                    Map<String, Object> resultInfo = Maps.newLinkedHashMap();
                    resultInfo.put("name", result.getName());
                    resultInfo.put("type", result.getType().toString());
                    callSite.put("result", resultInfo);
                }

                // Recursively analyze callee if within depth limit and not visited
                if (currentDepth < MAX_CALL_DEPTH - 1 && resolvedMethod != null) {
                    String calleeSig = resolvedMethod.getSignature();
                    if (!visitedMethods.contains(calleeSig)
                            && !resolvedMethod.isAbstract()
                            && !resolvedMethod.isNative()) {
                        // Create a copy of visited set for this branch
                        Set<String> branchVisited = Sets.newHybridSet();
                        branchVisited.addAll(visitedMethods);

                        Map<String, Object> nestedCallChain =
                                buildCallChainJsonRecursive(resolvedMethod,
                                        currentDepth + 1, branchVisited);
                        callSite.put("nestedCalls", nestedCallChain);
                    } else if (visitedMethods.contains(calleeSig)) {
                        callSite.put("nestedCalls", "CYCLE_DETECTED");
                    }
                }

                callSites.add(callSite);
            }
        }

        callChainJson.put("callSites", callSites);
        callChainJson.put("totalCalls", callIndex);
        callChainJson.put("maxDepth", MAX_CALL_DEPTH);

        // Build call sequence (order of calls) - flat view
        List<Map<String, Object>> callSequence = new ArrayList<>();
        for (int i = 0; i < callSites.size(); i++) {
            Map<String, Object> seqItem = Maps.newLinkedHashMap();
            seqItem.put("order", i);
            @SuppressWarnings("unchecked")
            Map<String, Object> callee = (Map<String, Object>) callSites.get(i).get("callee");
            seqItem.put("callee", callee.get("signature"));
            seqItem.put("invokeType", callSites.get(i).get("invokeType"));
            seqItem.put("lineNumber", callSites.get(i).get("lineNumber"));
            callSequence.add(seqItem);
        }
        callChainJson.put("callSequence", callSequence);

        return callChainJson;
    }

    /**
     * Gets the invoke type string for an Invoke statement.
     */
    private String getInvokeType(Invoke invoke) {
        if (invoke.isStatic()) {
            return "STATIC";
        } else if (invoke.isSpecial()) {
            return "SPECIAL";
        } else if (invoke.isVirtual()) {
            return "VIRTUAL";
        } else if (invoke.isInterface()) {
            return "INTERFACE";
        } else if (invoke.isDynamic()) {
            return "DYNAMIC";
        } else {
            return "UNKNOWN";
        }
    }

    /**
     * Exports the result to a JSON file.
     *
     * @return the output file
     */
    private File exportToJson(Map<String, Object> result, JMethod method) {
        // Generate file name from method info
        String className = method.getDeclaringClass().getSimpleName();
        String methodName = method.getName();
        String fileName = sanitizeFileName(className + "_" + methodName) + ".json";
        File outputFile = new File(outputDir, fileName);

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

                dataDeps.computeIfAbsent(tgt, k -> Sets.newHybridSet()).add(srcRef);
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

                // Get flow targets
                List<String> flows = nextHops.getOrDefault(nid, List.of("End"));
                String flow = String.join(", ", flows);
                if (flow.isEmpty()) {
                    flow = "End";
                }

                // Get dependencies
                Set<String> deps = dataDeps.getOrDefault(nid, Set.of());
                String depsStr = deps.isEmpty() ? "None" : String.join(", ", deps);

                // Format line (allow longer labels)
                String line = String.format("%-3d: %s | {%s} | {Uses: %s}",
                        idx, label, flow, depsStr);
                writer.println(line);
            }

            logger.info("Text graph exported to: {}", textFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to export graph to text: {}", e.getMessage());
        }
    }

    /**
     * Recursively prints call chain information to the text writer.
     *
     * @param writer the PrintWriter to write to
     * @param callChain the call chain data
     * @param indentLevel the current indentation level
     */
    @SuppressWarnings("unchecked")
    private void printCallChainRecursive(PrintWriter writer,
                                         Map<String, Object> callChain,
                                         int indentLevel) {
        String indent = "  ".repeat(indentLevel);
        String depthMarker = indentLevel == 0 ? "" : "L" + indentLevel + " ";

        // Get caller info
        Map<String, Object> caller = (Map<String, Object>) callChain.get("caller");
        String callerSig = (String) caller.get("signature");
        String callerClass = (String) caller.get("className");
        String callerMethod = (String) caller.get("methodName");
        String shortCallerClass = callerClass.contains(".")
                ? callerClass.substring(callerClass.lastIndexOf('.') + 1)
                : callerClass;

        // Print caller header
        if (indentLevel > 0) {
            writer.println(indent + "┌─ " + depthMarker + shortCallerClass + "." + callerMethod + "()");
        }

        List<Map<String, Object>> callSites =
                (List<Map<String, Object>>) callChain.get("callSites");
        int totalCalls = ((Number) callChain.get("totalCalls")).intValue();

        // Check for notes (abstract/native methods)
        String note = (String) callChain.get("note");
        if (note != null) {
            writer.println(indent + "│  Note: " + note);
            if (indentLevel > 0) {
                writer.println(indent + "└─────────");
            }
            return;
        }

        if (callSites == null || callSites.isEmpty()) {
            writer.println(indent + (indentLevel > 0 ? "│  " : "")
                    + "No method calls in this method.");
            if (indentLevel > 0) {
                writer.println(indent + "└─────────");
            }
            return;
        }

        // Print method info
        if (indentLevel == 0) {
            writer.println("Method: " + callerSig);
            writer.println("Total Direct Calls: " + totalCalls);
            writer.println("-".repeat(100));
        } else {
            writer.println(indent + "│  Calls: " + totalCalls);
        }

        // Print each call site
        for (int i = 0; i < callSites.size(); i++) {
            Map<String, Object> callSite = callSites.get(i);
            boolean isLast = (i == callSites.size() - 1);

            int callIdx = ((Number) callSite.get("callIndex")).intValue();
            int stmtIdx = ((Number) callSite.get("stmtIndex")).intValue();
            int lineNum = ((Number) callSite.get("lineNumber")).intValue();
            String invokeType = (String) callSite.get("invokeType");

            Map<String, Object> callee = (Map<String, Object>) callSite.get("callee");
            String calleeSig = (String) callee.get("signature");
            String calleeMethod = (String) callee.get("methodName");
            String calleeClass = (String) callee.get("className");
            boolean resolved = (Boolean) callee.get("resolved");

            String resolvedStr = resolved ? "✓" : "✗";
            String shortClass = calleeClass.contains(".")
                    ? calleeClass.substring(calleeClass.lastIndexOf('.') + 1)
                    : calleeClass;

            String prefix = indentLevel > 0 ? (indent + "│  ") : "";
            String connector = isLast ? "└── " : "├── ";

            // Print call info
            writer.printf("%s%s[%d] @L%d %-9s -> %s.%s %s%n",
                    prefix, connector, callIdx, lineNum, invokeType,
                    shortClass, calleeMethod, resolvedStr);

            // Print arguments
            List<Map<String, Object>> args =
                    (List<Map<String, Object>>) callSite.get("arguments");
            String subPrefix = indentLevel > 0
                    ? (indent + "│  " + (isLast ? "    " : "│   "))
                    : (isLast ? "    " : "│   ");

            if (args != null && !args.isEmpty()) {
                StringJoiner argsJoiner = new StringJoiner(", ");
                for (Map<String, Object> arg : args) {
                    String argType = (String) arg.get("type");
                    // Shorten type names
                    if (argType.contains(".")) {
                        argType = argType.substring(argType.lastIndexOf('.') + 1);
                    }
                    argsJoiner.add(arg.get("name") + ":" + argType);
                }
                writer.println(subPrefix + "Args: (" + argsJoiner + ")");
            }

            // Print result if any
            Map<String, Object> resultVar = (Map<String, Object>) callSite.get("result");
            if (resultVar != null) {
                String resultType = (String) resultVar.get("type");
                if (resultType.contains(".")) {
                    resultType = resultType.substring(resultType.lastIndexOf('.') + 1);
                }
                writer.println(subPrefix + "Result: " + resultVar.get("name") + ":" + resultType);
            }

            // Handle nested calls
            Object nestedCalls = callSite.get("nestedCalls");
            if (nestedCalls != null) {
                if ("CYCLE_DETECTED".equals(nestedCalls)) {
                    writer.println(subPrefix + "⟲ [Cycle detected - already visited]");
                } else if (nestedCalls instanceof Map) {
                    Map<String, Object> nested = (Map<String, Object>) nestedCalls;
                    List<Map<String, Object>> nestedCallSites =
                            (List<Map<String, Object>>) nested.get("callSites");
                    if (nestedCallSites != null && !nestedCallSites.isEmpty()) {
                        printCallChainRecursive(writer, nested, indentLevel + 1);
                    }
                }
            }

            // Add spacing between top-level calls
            if (indentLevel == 0 && !isLast) {
                writer.println();
            }
        }

        if (indentLevel > 0) {
            writer.println(indent + "└─────────");
        }
    }

    /**
     * Exports call chain in a concise format suitable for LLM prompts.
     * This is a separate file containing only call chain information, no IR code.
     * The output is saved as {baseName}.callchain.txt
     */
    @SuppressWarnings("unchecked")
    private void exportCallChainForPrompt(Map<String, Object> result, File jsonFile) {
        // Determine call chain output file path (same base name but with .callchain.txt extension)
        String jsonPath = jsonFile.getAbsolutePath();
        String callchainPath = jsonPath.endsWith(".json")
                ? jsonPath.substring(0, jsonPath.length() - 5) + ".callchain.txt"
                : jsonPath + ".callchain.txt";
        File callchainFile = new File(callchainPath);

        try (PrintWriter writer = new PrintWriter(new FileWriter(callchainFile))) {
            Map<String, Object> callChain = (Map<String, Object>) result.get("callChain");
            if (callChain == null) {
                writer.println("No call chain information available.");
                return;
            }

            // Get target method info
            Map<String, Object> caller = (Map<String, Object>) callChain.get("caller");
            String targetMethod = (String) caller.get("signature");
            String className = (String) caller.get("className");
            String methodName = (String) caller.get("methodName");

            // Header
            writer.println("Method Call Chain Analysis");
            writer.println("Target: " + methodName + "() in " + className);
            writer.println("Full Signature: " + targetMethod);
            writer.println();
            writer.println("Call Hierarchy (max depth: " + MAX_CALL_DEPTH + "):");
            writer.println();

            // Recursively print call chain (no IR code)
            printCallChainForPrompt(writer, callChain, 0);

            logger.info("Call chain exported to: {}", callchainFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to export call chain: {}", e.getMessage());
        }
    }

    /**
     * Recursively prints call chain in a concise format suitable for prompts.
     * Only prints call information, no IR statements.
     */
    @SuppressWarnings("unchecked")
    private void printCallChainForPrompt(PrintWriter writer,
                                         Map<String, Object> callChain,
                                         int depth) {
        if (depth > MAX_CALL_DEPTH - 1) {
            return;
        }

        String indent = "  ".repeat(depth);

        Map<String, Object> caller = (Map<String, Object>) callChain.get("caller");
        String callerClass = (String) caller.get("className");
        String callerMethod = (String) caller.get("methodName");

        // Simplify class name
        String shortClass = callerClass.contains(".")
                ? callerClass.substring(callerClass.lastIndexOf('.') + 1)
                : callerClass;

        // Print caller header only for depth > 0
        if (depth > 0) {
            writer.println(indent + "┌─ " + shortClass + "." + callerMethod + "()");
        }

        List<Map<String, Object>> callSites =
                (List<Map<String, Object>>) callChain.get("callSites");
        String note = (String) callChain.get("note");

        if (note != null) {
            writer.println(indent + "  Note: " + note);
            return;
        }

        if (callSites == null || callSites.isEmpty()) {
            if (depth > 0) {
                writer.println(indent + "  (no calls)");
                writer.println();
            }
            return;
        }

        // Print each call
        for (Map<String, Object> callSite : callSites) {
            Map<String, Object> callee = (Map<String, Object>) callSite.get("callee");
            String calleeClass = (String) callee.get("className");
            String calleeMethod = (String) callee.get("methodName");
            String invokeType = (String) callSite.get("invokeType");
            boolean resolved = (Boolean) callee.get("resolved");

            String shortCalleeClass = calleeClass.contains(".")
                    ? calleeClass.substring(calleeClass.lastIndexOf('.') + 1)
                    : calleeClass;

            // Build method signature line
            StringBuilder callLine = new StringBuilder();
            if (depth == 0) {
                callLine.append("→ ");
            } else {
                callLine.append(indent);
            }

            // Method name and type
            callLine.append(String.format("[%s] %s.%s(", invokeType, shortCalleeClass, calleeMethod));

            // Parameters (simplified)
            List<Map<String, Object>> args =
                    (List<Map<String, Object>>) callSite.get("arguments");
            if (args != null && !args.isEmpty()) {
                List<String> paramTypes = new ArrayList<>();
                for (Map<String, Object> arg : args) {
                    String paramType = (String) arg.get("type");
                    // Simplify type names
                    if (paramType.contains(".")) {
                        paramType = paramType.substring(paramType.lastIndexOf('.') + 1);
                    }
                    paramTypes.add(paramType);
                }
                callLine.append(String.join(", ", paramTypes));
            }

            callLine.append(")");

            // Return type
            String returnType = (String) callee.get("returnType");
            if (!"void".equals(returnType)) {
                if (returnType.contains(".")) {
                    returnType = returnType.substring(returnType.lastIndexOf('.') + 1);
                }
                callLine.append(" → ").append(returnType);
            }

            // Resolution status
            if (!resolved) {
                callLine.append(" [unresolved]");
            }

            writer.println(callLine.toString());

            // Handle nested calls
            Object nestedCalls = callSite.get("nestedCalls");
            if (nestedCalls != null && nestedCalls instanceof Map) {
                Map<String, Object> nested = (Map<String, Object>) nestedCalls;
                List<Map<String, Object>> nestedCallSites =
                        (List<Map<String, Object>>) nested.get("callSites");
                if (nestedCallSites != null && !nestedCallSites.isEmpty()) {
                    printCallChainForPrompt(writer, nested, depth + 1);
                    if (depth > 0) {
                        writer.println(indent + "└─");
                    }
                }
            }
        }

        if (depth > 0) {
            writer.println();
        }
    }

    /**
     * Sanitizes file name by replacing invalid characters.
     */
    private String sanitizeFileName(String name) {
        return name.replaceAll("[\\\\/:*?\"<>|]", "_");
    }
}

