"""采集器静态路由目录门禁；只依赖 Python 标准库，不执行前端源码。"""
import copy
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_alignment as alignment


BOUNDARIES = """
    {path:'/',redirect:'/overview/status'},
    {path:'/login',component:Login},
    {path:'/access-denied',component:Denied},
    {path:'/:pathMatch(.*)*',component:NotFound},
"""
BASE_PATHS = {"/", "/login", "/access-denied"}


def route_source(records="", boundaries=BOUNDARIES):
    return """
import {createRouter,createWebHistory,type RouteRecordRaw} from 'vue-router'
export function collectorRoutes(): RouteRecordRaw[] {
  return [
""" + boundaries + records + """
  ]
}
export function buildRouter(history=createWebHistory()) {
  const router=createRouter({history,scrollBehavior:()=>({top:0}),routes:collectorRoutes()})
  router.beforeEach(to=>{if(to.path==='/login')return; return true})
  return router
}
"""


class CollectorRouteTreeTests(unittest.TestCase):
    def reject(self, sources):
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                alignment.collector_route_paths(source)

    def test_real_tree_includes_parents_and_nine_leaf_views(self):
        self.assertEqual(alignment.collector_navigation_routes(ROOT), {
            "/", "/login", "/access-denied", "/overview", "/overview/status",
            "/network", "/network/interfaces", "/network/capture", "/network/archives", "/network/syslog",
            "/connection", "/connection/identity", "/rules", "/rules/samples", "/rules/tasks",
            "/response", "/response/devices",
        })

    def test_boundary_only_tree_is_static_and_catchall_is_not_a_business_path(self):
        self.assertEqual(alignment.collector_route_paths(route_source()), BASE_PATHS)

    def test_three_levels_resolve_relative_children_against_their_own_parent(self):
        source = route_source("""
          {path:'/network',redirect:'/network/capture',children:[
            {path:'capture',component:Layout,children:[
              {path:'interfaces',component:Page},
              {path:'filters',component:Page},
            ]},
            {path:'archives',component:Page},
          ]},
          {path:'/rules',redirect:'/rules/tasks',children:[{path:'tasks',component:Page}]},
        """)
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS | {
            "/network", "/network/capture", "/network/capture/interfaces", "/network/capture/filters",
            "/network/archives", "/rules", "/rules/tasks",
        })

    def test_absolute_child_replaces_prefix_and_grandchild_uses_absolute_parent(self):
        source = route_source("""
          {path:'/network',component:Layout,children:[
            {path:'/traffic',component:Layout,children:[{path:'sessions',component:Page}]},
            {path:'interfaces',component:Page},
          ]},
        """)
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS | {
            "/network", "/traffic", "/traffic/sessions", "/network/interfaces",
        })

    def test_redirect_parents_and_empty_children_remain_declared_paths(self):
        source = route_source("""
          {path:'/overview',redirect:to=>({path:'/overview/status',query:to.query}),children:[
            {path:'status',component:Page},
          ]},
          {path:'/rules',component:Page,children:[]},
        """)
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS | {"/overview", "/overview/status", "/rules"})

    def test_comments_strings_and_nested_path_fields_do_not_invent_routes(self):
        source = route_source("""
          // {path:'/comment',children:[{path:'invented',component:Page}]}
          /* function collectorRoutes(){ return [{path:'/comment'}] }
             createRouter({routes:[]}) */
          {'path':'/overview',component:()=>({path:'/component-only'}),
           meta:{title:'collectorRoutes',description:'function',path:'/meta-only',close:'}',open:'['},
           props:{path:'/props-only',children:[{path:'/props-child'}]}},
          {path:'/network',redirect:{path:'/redirect-only',query:{path:'/query-only'}}},
        """) + "\nconst note='createRouter('"
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS | {"/overview", "/network"})

    def test_static_quoted_keys_trailing_commas_and_explicit_history_are_supported(self):
        source = route_source("{'path':'/rules','component':Page,'children':[],},")
        source = source.replace("{history,scrollBehavior", "{'history':createWebHistory(),scrollBehavior")
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS | {"/rules"})

    def test_optional_return_type_and_semicolon_are_supported(self):
        source = route_source().replace("(): RouteRecordRaw[]", "()").replace("  ]\n}", "  ];\n}")
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS)

    def test_missing_root_login_denial_and_catchall_are_rejected(self):
        for line in BOUNDARIES.splitlines():
            if line.strip():
                with self.subTest(boundary=line):
                    self.reject([route_source(boundaries=BOUNDARIES.replace(line, ""))])

    def test_duplicate_paths_are_rejected_after_resolution(self):
        self.reject([route_source(records) for records in (
            "{path:'/network',component:Page},{path:'/network',component:Page},",
            "{path:'/network',component:Page,children:[{path:'capture',component:Page},{path:'capture',component:Page}]},",
            "{path:'/network',component:Page,children:[{path:'capture',component:Page}]},{path:'/network/capture',component:Page},",
            "{path:'/network',component:Page,children:[{path:'/traffic',component:Page}]},{path:'/traffic',component:Page},",
        )])

    def test_duplicate_and_dynamic_names_cannot_silently_replace_route_records(self):
        self.reject([route_source(records) for records in (
            "{path:'/network',name:'same',component:Page},{path:'/rules',name:'same',component:Page},",
            "{path:'/network',component:Page,children:[{path:'capture',name:'same',component:Page}]},{path:'/rules',name:'same',component:Page},",
            "{path:'/network',name:dynamicName,component:Page},",
            "{path:'/network',name:'',component:Page},",
        )])
        self.assertEqual(alignment.collector_route_paths(route_source("{path:'/network',name:'network',component:Page},")), BASE_PATHS | {"/network"})

    def test_unsafe_and_dynamic_path_segments_are_rejected(self):
        invalid = ("", "../capture", "./capture", ".", "..", "capture/../tasks", "/capture/./tasks", "capture/",
                   "//capture", "/capture//tasks", "capture?view=tasks", "capture#tasks", "/capture/:id", "/capture/*",
                   "/CAPTURE", "/采集", "/capture/%2e%2e/tasks", "/capture\\u002ftasks")
        for path in invalid:
            with self.subTest(path=path):
                self.reject([route_source("{path:'/network',component:Page,children:[{path:'" + path + "',component:Page}]},")])
        self.reject([route_source("{path:'relative',component:Page},")])

    def test_api_assets_and_unknown_page_probe_cannot_be_claimed(self):
        self.reject([route_source("{path:'" + path + "',component:Page},") for path in (
            "/api", "/api/local/v1", "/assets", "/assets/app", "/invalid-page",
        )])

    def test_dynamic_path_expressions_are_rejected(self):
        self.reject([route_source("{path:" + path + ",component:Page},") for path in (
            "routePath", "'/network' + '/capture'", "`/network`", "resolvePath()", "enabled?'/network':'/rules'", "1", "null",
        )])

    def test_dynamic_and_malformed_child_arrays_are_rejected(self):
        self.reject([route_source("{path:'/network',component:Page,children:" + children + "},") for children in (
            "nestedRoutes", "loadRoutes()", "[...nestedRoutes]", "[{path:'capture',component:Page}].map(mapper)",
            "[{path:'capture',component:Page}].concat(other)", "enabled?[]:[]", "null", "[,]", "[{path:'capture',component:Page},,]",
        )])

    def test_unknown_computed_spread_shorthand_and_duplicate_properties_fail(self):
        self.reject([route_source(record) for record in (
            "{path:'/network',component:Page,alias:'/capture'},",
            "{path:'/network',component:Page,unknown:true},",
            "{...base,path:'/network',component:Page},",
            "{path:'/network',...base,component:Page},",
            "{['path']:'/network',component:Page},",
            "{get path(){return '/network'},component:Page},",
            "{path:'/network',component},",
            "{path:'/network',path:'/rules',component:Page},",
            "{path:'/network',component:Page,children:[],children:[]},",
            "{path:'/network'},",
        )])

    def test_catchall_must_be_exact_unique_top_level_and_render_a_boundary(self):
        self.reject([
            route_source("{path:'/:pathMatch(.*)*',component:Other},"),
            route_source(boundaries=BOUNDARIES.replace("component:NotFound", "redirect:'/login'")),
            route_source(boundaries=BOUNDARIES.replace("component:NotFound", "component:NotFound,children:[]")),
            route_source("{path:'/network',component:Page,children:[{path:'/:pathMatch(.*)*',component:NotFound}]},"),
            route_source(boundaries=BOUNDARIES.replace("/:pathMatch(.*)*", "/:pathMatch(.*)")),
        ])

    def test_route_factory_cannot_be_async_conditional_parameterized_or_transformed(self):
        original = route_source()
        self.reject([
            original.replace("function collectorRoutes", "async function collectorRoutes"),
            original.replace("function collectorRoutes", "function* collectorRoutes"),
            original.replace("collectorRoutes():", "collectorRoutes(options):"),
            original.replace("  return [", "  if(enabled)return []; return ["),
            original.replace("  return [", "  const records=[]; return ["),
            original.replace("  ]\n}", "  ].filter(enabled)\n}"),
            original.replace("  ]\n}", "  ]; routerMutation();\n}"),
            original.replace("export function collectorRoutes", "if(enabled){function collectorRoutes").replace("export function buildRouter", "}\nexport function buildRouter"),
        ])

    def test_return_newline_comments_and_string_decoys_cannot_impersonate_syntax(self):
        original = route_source()
        self.reject([
            original.replace("return [", "return\n[", 1),
            original.replace("return [", "return\u2028[", 1),
            original.replace("return [", "return\u2029[", 1),
            original.replace("return [", "return /*\n*/[", 1),
            original.replace("return [", "return // records\n[", 1),
            original.replace("return [", "'return' [", 1),
            original.replace("function collectorRoutes", "'function' collectorRoutes", 1),
            original.replace("const router=createRouter(", "const router='createRouter'(", 1),
        ])

    def test_registration_must_directly_use_static_factory_and_options(self):
        original = route_source()
        self.reject([
            original.replace("routes:collectorRoutes()", "routes:collectorRoutes().filter(enabled)"),
            original.replace("routes:collectorRoutes()", "routes:decorate(collectorRoutes())"),
            original.replace("routes:collectorRoutes()", "routes:collectorRoutes(options)"),
            original.replace("routes:collectorRoutes()", "routes"),
            original.replace("routes:collectorRoutes()", "routes:[]"),
            original.replace("routes:collectorRoutes()", "routes:collectorRoutes(),routes:[]"),
            original.replace("routes:collectorRoutes()", "routes:collectorRoutes(),...otherOptions"),
            original.replace("routes:collectorRoutes()", "routes:collectorRoutes(),plugins:extensions"),
            original.replace("createRouter({", "createRouter(loadOptions({").replace("routes:collectorRoutes()})", "routes:collectorRoutes()}))"),
            original.replace("routes:collectorRoutes()})", "routes:collectorRoutes()},more)"),
            original.replace("{history,scrollBehavior", "{scrollBehavior"),
        ])

    def test_extra_factory_references_and_router_registration_are_rejected(self):
        original = route_source()
        self.reject([
            original + "\nconst extra=collectorRoutes()",
            original + "\nconst alias=collectorRoutes",
            original + "\nfunction collectorRoutes(){return []}",
            original + "\nconst extra=createRouter({history,routes:[]})",
        ])

    def test_runtime_route_changes_and_router_instance_escape_are_rejected(self):
        original = route_source()
        self.reject([original.replace("  return router", mutation + "\n  return router") for mutation in (
            "router.addRoute({path:'/hidden',component:Page})",
            "router.removeRoute('name')",
            "router.clearRoutes()",
            "router['addRoute']({path:'/hidden',component:Page})",
            "router.options.routes.push({path:'/hidden',component:Page})",
            "router.options['routes'].push({path:'/hidden',component:Page})",
            "router[method]({path:'/hidden',component:Page})",
            "mutate(router)",
            "const alias=router",
            "router=otherRouter",
            "// comment\rrouter.addRoute({path:'/hidden',component:Page})",
            "// comment\u2028router.addRoute({path:'/hidden',component:Page})",
            "// comment\u2029router.addRoute({path:'/hidden',component:Page})",
        )])

    def test_supported_guard_hooks_do_not_erase_declared_paths(self):
        source = route_source().replace("  return router", "  router.beforeResolve(()=>true)\n  router.afterEach(()=>{})\n  router.onError(()=>{})\n  return router")
        self.assertEqual(alignment.collector_route_paths(source), BASE_PATHS)

    def test_unclosed_strings_comments_and_brackets_are_rejected(self):
        original = route_source()
        self.reject([
            original + "\n/* unterminated",
            original + "\nconst note='unterminated",
            original + "\nconst note='bad\nline'",
            original + "\nconst note=([)]",
            original + "\nconst note={",
            original.replace("return [", "return [[", 1),
            original.replace("return [", "return [,", 1),
            original + "\nconst matcher=/network/",
        ])

    def test_size_token_and_nesting_budgets_reject_unbounded_configuration(self):
        nested = "{path:'leaf',component:Page}"
        for index in range(18):
            nested = "{path:'level-" + str(index) + "',component:Page,children:[" + nested + "]}"
        self.reject([
            " " * (512 * 1024 + 1),
            ";" * 30001,
            "(" * 129 + ")" * 129 + route_source(),
            route_source("{path:'/nested',component:Page,children:[" + nested + "]},"),
        ])


class CollectorRouteAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        for role in ("platform", "collector"):
            (self.root / "web" / role / "src").mkdir(parents=True)
        (self.root / "web/platform/src/router.ts").write_text("const routes=[{path:'/login',component:Login}]")
        self.source = route_source("""
          {path:'/network',redirect:'/network/interfaces',children:[
            {path:'interfaces',component:Page},{path:'capture',component:Page},
          ]},
          {path:'/rules',redirect:'/rules/tasks',children:[{path:'tasks',component:Page}]},
        """)
        (self.root / "web/collector/src/router.ts").write_text(self.source)
        self.paths = BASE_PATHS | {"/network", "/network/interfaces", "/network/capture", "/rules", "/rules/tasks"}
        self.routes = {"platform": ["/login", "/invalid-page"], "collector": sorted(self.paths) + ["/invalid-page", "/network?view=tasks", "/network?view=capture"]}
        self.inventory = {"capabilities": [{"pages": ["collector:/rules/tasks", "collector:/network?view=tasks"]}]}

    def test_exact_parent_leaf_and_legacy_query_catalog_is_accepted(self):
        alignment.validate_routes(self.root, self.routes, self.inventory)

    def test_every_parent_leaf_and_boundary_is_required(self):
        for path in sorted(self.paths | {"/invalid-page"}):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "collector"):
                routes = copy.deepcopy(self.routes)
                routes["collector"] = [item for item in routes["collector"] if item.split("?", 1)[0] != path]
                alignment.validate_routes(self.root, routes, self.inventory)

    def test_duplicate_unknown_or_invalid_inventory_routes_are_rejected(self):
        for extra in ("/rules/tasks", "/unregistered", "/unregistered?view=tasks", "https://external.invalid/rules/tasks", "//external.invalid/rules/tasks", "/rules/tasks#hidden"):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "collector"):
                routes = copy.deepcopy(self.routes)
                routes["collector"].append(extra)
                alignment.validate_routes(self.root, routes, self.inventory)

    def test_capability_pages_must_reference_an_exact_catalog_entry(self):
        for page in ("collector:/rules/tasks?view=missing", "collector:/unknown", "unknown:/rules/tasks"):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, "能力页面"):
                alignment.validate_routes(self.root, self.routes, {"capabilities": [{"pages": [page]}]})

    def test_unknown_dynamic_collector_config_fails_before_catalog_can_hide_it(self):
        (self.root / "web/collector/src/router.ts").write_text(self.source.replace("children:[", "children:makeRoutes([", 1).replace("{path:'interfaces',component:Page},{path:'capture',component:Page},\n          ]", "{path:'interfaces',component:Page},{path:'capture',component:Page},\n          ])", 1))
        with self.assertRaisesRegex(ValueError, "children"):
            alignment.validate_routes(self.root, self.routes, self.inventory)


if __name__ == "__main__":
    unittest.main()
